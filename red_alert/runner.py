from collections.abc import Callable, Sequence

import httpx

from red_alert.attacks import AttackScenario
from red_alert.graph import OnStep, run_attempt
from red_alert.models import AttemptResult, RunReport
from red_alert.planner import PayloadPlanner
from red_alert.stand_client import StandClient
from red_alert.tracing import TraceSink

__all__ = ["run_attempt", "run_attack"]

NOTES_LIMIT = 2000


def run_attack(
    *,
    target: str,
    api_key: str,
    victim_api_key: str,
    scenario: AttackScenario,
    attempts: int,
    http_client: httpx.Client,
    planner: PayloadPlanner,
    auth_mode: str = "vulnerable",
    on_step: OnStep | None = None,
    on_attempt_done: Callable[[AttemptResult], None] | None = None,
    sink: TraceSink | None = None,
    secrets: Sequence[str] = (),
) -> RunReport:
    attacker = StandClient(target, api_key, http_client, auth_mode=auth_mode)
    victim = StandClient(target, victim_api_key, http_client, auth_mode=auth_mode)
    results: list[AttemptResult] = []
    prior_notes = ""
    for index in range(1, attempts + 1):
        if sink is None:
            result = run_attempt(
                attacker,
                victim,
                scenario,
                index,
                planner,
                on_step,
                prior_notes,
            )
        else:
            with sink.trace_attempt(
                scenario=scenario.name,
                flow=scenario.flow,
                vulnerability=scenario.vulnerability,
                auth_mode=auth_mode,
                attempt_index=index,
                secrets=secrets,
            ) as graph_trace:
                result = run_attempt(
                    attacker,
                    victim,
                    scenario,
                    index,
                    planner,
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
        target=target,
        auth_mode=auth_mode,
        attempts=results,
    )


def _attempt_notes(result: AttemptResult) -> str:
    parts = [f"попытка {result.attempt_index}: success={result.success}"]
    finalize = next((step for step in reversed(result.steps) if step.name == "finalize"), None)
    trigger = next((step for step in reversed(result.steps) if step.name == "trigger"), None)
    payload = next((step for step in reversed(result.steps) if step.name == "payload"), None)
    if finalize is not None and finalize.response_body is not None:
        parts.append(f"finalize={finalize.response_body}")
    if trigger is not None and trigger.response_body is not None:
        parts.append(f"victim={trigger.response_body}")
    elif payload is not None and payload.response_body is not None:
        parts.append(f"attacker={payload.response_body}")
    last = result.steps[-1] if result.steps else None
    if last is not None and last.error:
        parts.append(f"error={last.error}")
    return "; ".join(parts)[:NOTES_LIMIT]
