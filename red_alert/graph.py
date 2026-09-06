import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
from langgraph.graph import END, START, StateGraph

from red_alert.attacks import AttackScenario
from red_alert.dialogue import DialogueTracer, NullDialogue
from red_alert.image_payload import payload_user_content
from red_alert.judge import AttackJudge, JudgeContext
from red_alert.models import AttackStep, AttemptResult
from red_alert.planner import PayloadPlanner, PlannerContext, build_planner_messages
from red_alert.target import PRINCIPAL_EVAL, PRINCIPAL_TARGET, Target, TargetTurn, UserContent

OnStep = Callable[[AttackStep], None]

ACTOR_TARGET = PRINCIPAL_TARGET
ACTOR_EVAL = PRINCIPAL_EVAL
ACTOR_PLANNER = "planner"
ACTOR_JUDGE = "judge"


@dataclass
class AttemptState:
    attempt_index: int
    target_session_id: str
    eval_session_id: str
    injects: int
    payload: str = ""
    last_assistant: str = ""
    target_response: str = ""
    eval_response: str = ""
    last_finalize: object | None = None
    prior_notes: str = ""
    steps: list[AttackStep] = field(default_factory=list)
    error: str | None = None
    success: bool = False


def _decode_body(response: httpx.Response) -> object:
    try:
        return response.json()
    except ValueError:
        return response.text


def _assistant_text(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message") or {}
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    text = content if isinstance(content, str) else ""
    tool_calls = message.get("tool_calls")
    if tool_calls:
        dumped = json.dumps(tool_calls, ensure_ascii=False)
        return f"{text}\n{dumped}".strip() if text else dumped
    return text


def _http_step(
    *,
    name: str,
    method: str,
    url: str,
    actor: str,
    request_body: dict | None,
    response: httpx.Response,
) -> AttackStep:
    error = None if response.is_success else f"HTTP {response.status_code}"
    return AttackStep(
        name=name,
        method=method,
        url=url,
        actor=actor,
        request_body=request_body,
        response_body=_decode_body(response),
        status_code=response.status_code,
        error=error,
    )


def _error_step(
    *,
    name: str,
    method: str,
    url: str,
    actor: str,
    request_body: dict | None,
    error: str,
) -> AttackStep:
    return AttackStep(
        name=name,
        method=method,
        url=url,
        actor=actor,
        request_body=request_body,
        error=error,
    )


def step_from_turn(*, name: str, actor: str, turn: TargetTurn) -> AttackStep:
    if turn.response is None:
        return _error_step(
            name=name,
            method=turn.method,
            url=turn.url,
            actor=actor,
            request_body=turn.request_body,
            error=turn.error or "ошибка цели",
        )
    step = _http_step(
        name=name,
        method=turn.method,
        url=turn.url,
        actor=actor,
        request_body=turn.request_body,
        response=turn.response,
    )
    if turn.error and not step.error:
        return step.model_copy(update={"error": turn.error})
    return step


def _emit(on_step: OnStep | None, step: AttackStep) -> None:
    if on_step is not None:
        on_step(step)


def _send_payload(
    target: Target,
    payload: UserContent,
    session_id: str,
    steps: list[AttackStep],
    on_step: OnStep | None = None,
) -> tuple[str | None, str]:
    turn = target.chat(
        principal=ACTOR_TARGET,
        session_id=session_id,
        user_content=payload,
    )
    step = step_from_turn(name="payload", actor=ACTOR_TARGET, turn=turn)
    steps.append(step)
    _emit(on_step, step)
    if step.error:
        return step.error, ""
    return None, _assistant_text(step.response_body)


def build_attempt_graph(
    target: Target,
    scenario: AttackScenario,
    planner: PayloadPlanner,
    judge: AttackJudge,
    on_step: OnStep | None = None,
    dialogue: DialogueTracer | None = None,
):
    log = dialogue or NullDialogue()

    def adapt(state: AttemptState) -> dict:
        steps = list(state.steps)
        context = PlannerContext(
            goal=scenario.goal,
            inject_index=state.injects + 1,
            last_payload=state.payload or None,
            last_assistant=state.last_assistant or None,
            last_finalize=state.last_finalize,
            prior_notes=state.prior_notes,
            examples=scenario.payloads,
        )
        with log.planner(messages=build_planner_messages(context)) as observed:
            turn = planner.plan(context)
            model = turn.request_body.get("model") if isinstance(turn.request_body, dict) else None
            observed.finish(
                output=turn.payload,
                error=turn.error,
                model=model if isinstance(model, str) else None,
            )
        if turn.response is None:
            step = _error_step(
                name="adapt",
                method="POST",
                url=turn.url,
                actor=ACTOR_PLANNER,
                request_body=turn.request_body,
                error=turn.error or "ошибка планировщика",
            )
        else:
            step = _http_step(
                name="adapt",
                method="POST",
                url=turn.url,
                actor=ACTOR_PLANNER,
                request_body=turn.request_body,
                response=turn.response,
            )
            if turn.error:
                step = step.model_copy(update={"error": turn.error})
        steps.append(step)
        _emit(on_step, step)
        if turn.error:
            return {"steps": steps, "error": turn.error, "payload": ""}
        return {"steps": steps, "error": None, "payload": turn.payload}

    def inject(state: AttemptState) -> dict:
        steps = list(state.steps)
        target_session_id = f"ra-target-{uuid.uuid4().hex[:12]}"
        log.begin_dialogue(name="target", session_id=target_session_id)
        try:
            user_content = payload_user_content(scenario, state.payload)
        except OSError as exc:
            step = _error_step(
                name="payload",
                method="POST",
                url="",
                actor=ACTOR_TARGET,
                request_body=None,
                error=str(exc),
            )
            steps.append(step)
            _emit(on_step, step)
            log.end_dialogue()
            return {
                "target_session_id": target_session_id,
                "injects": state.injects + 1,
                "last_assistant": "",
                "steps": steps,
                "error": str(exc),
                "success": False,
            }
        with log.stand(
            user=state.payload,
            actor=ACTOR_TARGET,
            session_id=target_session_id,
        ) as observed:
            error, assistant = _send_payload(
                target,
                user_content,
                target_session_id,
                steps,
                on_step,
            )
            observed.finish(output=assistant, error=error)
        log.add_message("user", state.payload)
        log.add_message("assistant", assistant)
        if error or scenario.flow == "probe":
            log.end_dialogue()
        return {
            "target_session_id": target_session_id,
            "injects": state.injects + 1,
            "last_assistant": assistant,
            "target_response": assistant,
            "steps": steps,
            "error": error,
            "success": False,
        }

    def persist(state: AttemptState) -> dict:
        steps = list(state.steps)
        target_session_id = state.target_session_id
        with log.persist(session_id=target_session_id) as observed:
            turn = target.persist(
                principal=ACTOR_TARGET,
                session_id=target_session_id,
            )
            if turn is None:
                observed.finish()
                log.end_dialogue()
                return {"steps": steps, "error": None, "last_finalize": None}
            persist_step = step_from_turn(name="persist", actor=ACTOR_TARGET, turn=turn)
            steps.append(persist_step)
            _emit(on_step, persist_step)
            if persist_step.error:
                observed.finish(output=persist_step.response_body, error=persist_step.error)
                log.end_dialogue()
                return {"steps": steps, "error": persist_step.error, "last_finalize": None}
            observed.finish(output=persist_step.response_body)
            log.set_persist(persist_step.response_body)
            log.end_dialogue()
        return {
            "steps": steps,
            "error": None,
            "last_finalize": persist_step.response_body,
        }

    def evaluate(state: AttemptState) -> dict:
        steps = list(state.steps)
        eval_session_id = state.eval_session_id
        user = target.eval_prompt or scenario.trigger
        if not user:
            return {"steps": steps, "error": None, "eval_response": ""}
        log.begin_dialogue(name="eval", session_id=eval_session_id)
        with log.stand(user=user, actor=ACTOR_EVAL, session_id=eval_session_id) as observed:
            turn = target.chat(
                principal=ACTOR_EVAL,
                session_id=eval_session_id,
                user_content=user,
            )
            eval_step = step_from_turn(name="eval", actor=ACTOR_EVAL, turn=turn)
            steps.append(eval_step)
            _emit(on_step, eval_step)
            assistant = _assistant_text(eval_step.response_body)
            if eval_step.error:
                observed.finish(output=assistant, error=eval_step.error)
                log.add_message("user", user)
                log.add_message("assistant", assistant)
                log.end_dialogue()
                return {"steps": steps, "error": eval_step.error, "success": False}
            observed.finish(output=assistant)
            log.add_message("user", user)
            log.add_message("assistant", assistant)
            log.end_dialogue()
        return {
            "steps": steps,
            "error": None,
            "last_assistant": assistant,
            "eval_response": assistant,
            "success": False,
        }

    def judge_result(state: AttemptState) -> dict:
        steps = list(state.steps)
        turn = judge.judge(
            JudgeContext(
                success_check=scenario.success_check,
                target_response=state.target_response,
                eval_response=state.eval_response or None,
            )
        )
        if turn.response is None:
            step = _error_step(
                name="judge",
                method="POST",
                url=turn.url,
                actor=ACTOR_JUDGE,
                request_body=turn.request_body,
                error=turn.error or "ошибка судьи",
            )
        else:
            step = _http_step(
                name="judge",
                method="POST",
                url=turn.url,
                actor=ACTOR_JUDGE,
                request_body=turn.request_body,
                response=turn.response,
            )
            if turn.error:
                step = step.model_copy(update={"error": turn.error})
        steps.append(step)
        _emit(on_step, step)
        return {
            "steps": steps,
            "error": turn.error,
            "success": turn.success if turn.error is None else False,
        }

    def after_adapt(state: AttemptState) -> str:
        return END if state.error else "inject"

    def after_inject(state: AttemptState) -> str:
        if state.error:
            return END
        if scenario.flow != "probe":
            return "persist"
        return "eval" if target.eval_prompt else "judge"

    def after_persist(state: AttemptState) -> str:
        if state.error:
            return END
        return "eval"

    def after_judge(state: AttemptState) -> str:
        if state.error:
            return END
        if state.success or state.injects >= scenario.max_injects:
            return END
        return "adapt"

    graph = StateGraph(AttemptState)
    graph.add_node("adapt", adapt)
    graph.add_node("inject", inject)
    graph.add_node("persist", persist)
    graph.add_node("eval", evaluate)
    graph.add_node("judge", judge_result)
    graph.add_edge(START, "adapt")
    graph.add_conditional_edges("adapt", after_adapt)
    graph.add_conditional_edges("inject", after_inject)
    graph.add_conditional_edges("persist", after_persist)
    graph.add_edge("eval", "judge")
    graph.add_conditional_edges("judge", after_judge)
    return graph.compile()


def run_attempt(
    target: Target,
    scenario: AttackScenario,
    attempt_index: int,
    planner: PayloadPlanner,
    judge: AttackJudge,
    on_step: OnStep | None = None,
    prior_notes: str = "",
    invoke_config: dict | None = None,
    on_graph_tick: Callable[[], None] | None = None,
    dialogue: DialogueTracer | None = None,
    prefix_steps: list[AttackStep] | None = None,
) -> AttemptResult:
    graph = build_attempt_graph(target, scenario, planner, judge, on_step, dialogue)
    initial = {
        "attempt_index": attempt_index,
        "target_session_id": "",
        "eval_session_id": f"ra-eval-{uuid.uuid4().hex[:12]}",
        "injects": 0,
        "payload": "",
        "last_assistant": "",
        "target_response": "",
        "eval_response": "",
        "last_finalize": None,
        "prior_notes": prior_notes,
        "steps": list(prefix_steps or []),
        "error": None,
        "success": False,
    }
    config = invoke_config or {}
    if config.get("callbacks"):
        state = None
        for state in graph.stream(initial, config=config, stream_mode="values"):
            if on_graph_tick is not None:
                on_graph_tick()
        if state is None:
            state = graph.invoke(initial, config=config)
    else:
        state = graph.invoke(initial, config=config)
    return AttemptResult(
        attempt_index=state["attempt_index"],
        success=bool(state["success"]),
        target_session_id=state["target_session_id"],
        eval_session_id=state["eval_session_id"],
        steps=list(state["steps"]),
    )
