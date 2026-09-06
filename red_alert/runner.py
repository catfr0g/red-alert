from collections.abc import Callable, Mapping, Sequence

import httpx

from red_alert.attacks import AttackScenario
from red_alert.dialogue import DialogueTracer, NullDialogue
from red_alert.graph import ACTOR_TARGET, OnStep, run_attempt, step_from_turn
from red_alert.judge import AttackJudge
from red_alert.models import AttackStep, AttemptResult, RunReport
from red_alert.planner import PayloadPlanner
from red_alert.profile import StandProfile
from red_alert.profile_target import ProfileTarget
from red_alert.target import ResetError, Target
from red_alert.tracing import TraceSink

__all__ = ["run_attempt", "run_attack"]

NOTES_LIMIT = 2000
ISOLATION_ON = "on"
ISOLATION_OFF = "off"


def run_attack(
    *,
    profile: StandProfile,
    environ: Mapping[str, str],
    scenario: AttackScenario,
    attempts: int,
    http_client: httpx.Client,
    planner: PayloadPlanner,
    judge: AttackJudge,
    isolation: str = ISOLATION_ON,
    on_step: OnStep | None = None,
    on_attempt_done: Callable[[AttemptResult], None] | None = None,
    sink: TraceSink | None = None,
    secrets: Sequence[str] = (),
) -> RunReport:
    stand = ProfileTarget(
        profile,
        scenario.name,
        environ,
        http_client,
    )
    results: list[AttemptResult] = []
    prior_notes = ""
    for index in range(1, attempts + 1):
        if sink is None:
            result = _run_one(
                stand,
                scenario,
                index,
                planner,
                judge,
                isolation,
                on_step,
                prior_notes,
            )
        else:
            with sink.trace_attempt(
                scenario=scenario.name,
                flow=scenario.flow,
                vulnerability=scenario.vulnerability,
                attempt_index=index,
                secrets=secrets,
                isolation=isolation,
            ) as graph_trace:
                result = _run_one(
                    stand,
                    scenario,
                    index,
                    planner,
                    judge,
                    isolation,
                    on_step,
                    prior_notes,
                    invoke_config=graph_trace.invoke_config,
                    on_graph_tick=graph_trace.on_tick,
                    dialogue=graph_trace.dialogue,
                )
                graph_trace.complete(result)
        results.append(result)
        prior_notes = _attempt_notes(result)
        if on_attempt_done is not None:
            on_attempt_done(result)
    return RunReport(
        scenario=scenario.name,
        target=stand.target_endpoint,
        isolation=isolation,
        attempts=results,
    )


def _run_one(
    stand: Target,
    scenario: AttackScenario,
    index: int,
    planner: PayloadPlanner,
    judge: AttackJudge,
    isolation: str,
    on_step: OnStep | None,
    prior_notes: str,
    invoke_config: dict | None = None,
    on_graph_tick: Callable[[], None] | None = None,
    dialogue: DialogueTracer | None = None,
) -> AttemptResult:
    prefix: list[AttackStep] = []
    if isolation == ISOLATION_ON:
        prefix = _isolate(stand, on_step, dialogue)
    return run_attempt(
        stand,
        scenario,
        index,
        planner,
        judge,
        on_step,
        prior_notes,
        invoke_config=invoke_config,
        on_graph_tick=on_graph_tick,
        dialogue=dialogue,
        prefix_steps=prefix,
    )


def _isolate(
    stand: Target,
    on_step: OnStep | None,
    dialogue: DialogueTracer | None,
) -> list[AttackStep]:
    log = dialogue or NullDialogue()
    with log.isolate() as observed:
        turn = stand.isolate()
        if turn is None:
            observed.finish()
            return []
        step = step_from_turn(name="isolate", actor=ACTOR_TARGET, turn=turn)
        if on_step is not None:
            on_step(step)
        if step.error:
            observed.finish(output=step.response_body, error=step.error)
            raise ResetError(f"Reset не выполнен: {step.error}", step)
        observed.finish(output=step.response_body)
    return [step]


def _attempt_notes(result: AttemptResult) -> str:
    parts = [f"попытка {result.attempt_index}: success={result.success}"]
    persist = next((step for step in reversed(result.steps) if step.name == "persist"), None)
    evaluation = next((step for step in reversed(result.steps) if step.name == "eval"), None)
    payload = next((step for step in reversed(result.steps) if step.name == "payload"), None)
    if persist is not None and persist.response_body is not None:
        parts.append(f"persist={persist.response_body}")
    if evaluation is not None and evaluation.response_body is not None:
        parts.append(f"eval={evaluation.response_body}")
    elif payload is not None and payload.response_body is not None:
        parts.append(f"target={payload.response_body}")
    last = result.steps[-1] if result.steps else None
    if last is not None and last.error:
        parts.append(f"error={last.error}")
    return "; ".join(parts)[:NOTES_LIMIT]
