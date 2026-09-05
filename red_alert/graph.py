import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
from langgraph.graph import END, START, StateGraph

from red_alert.attacks import AttackScenario
from red_alert.dialogue import DialogueTracer, NullDialogue, persist_view
from red_alert.models import AttackStep, AttemptResult
from red_alert.planner import PayloadPlanner, PlannerContext, build_planner_messages
from red_alert.target import PRINCIPAL_ATTACKER, PRINCIPAL_VICTIM, Target, TargetTurn

OnStep = Callable[[AttackStep], None]

ACTOR_ATTACKER = PRINCIPAL_ATTACKER
ACTOR_VICTIM = PRINCIPAL_VICTIM
ACTOR_PLANNER = "planner"


@dataclass
class AttemptState:
    attempt_index: int
    session_a: str
    session_b: str
    injects: int
    payload: str = ""
    last_assistant: str = ""
    last_finalize: object | None = None
    prior_notes: str = ""
    steps: list[AttackStep] = field(default_factory=list)
    error: str | None = None
    usable_policy: bool = False
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
    return content if isinstance(content, str) else ""


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
    payload: str,
    session_id: str,
    steps: list[AttackStep],
    on_step: OnStep | None = None,
) -> tuple[str | None, str]:
    turn = target.chat(
        principal=ACTOR_ATTACKER,
        session_id=session_id,
        user_content=payload,
    )
    step = step_from_turn(name="payload", actor=ACTOR_ATTACKER, turn=turn)
    steps.append(step)
    _emit(on_step, step)
    if step.error:
        return step.error, ""
    return None, _assistant_text(step.response_body)


def build_attempt_graph(
    target: Target,
    scenario: AttackScenario,
    planner: PayloadPlanner,
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
        session_a = f"ra-a-{uuid.uuid4().hex[:12]}"
        log.begin_dialogue(name="attacker", session_id=session_a)
        with log.stand(user=state.payload, actor="attacker", session_id=session_a) as observed:
            error, assistant = _send_payload(target, state.payload, session_a, steps, on_step)
            observed.finish(output=assistant, error=error)
        log.add_message("user", state.payload)
        log.add_message("assistant", assistant)
        if error or scenario.flow == "probe":
            log.end_dialogue()
        success = False
        if scenario.flow == "probe" and not error:
            success = scenario.is_success(assistant)
        return {
            "session_a": session_a,
            "injects": state.injects + 1,
            "last_assistant": assistant,
            "steps": steps,
            "error": error,
            "usable_policy": False,
            "success": success,
        }

    def persist(state: AttemptState) -> dict:
        steps = list(state.steps)
        session_a = state.session_a
        with log.persist(session_id=session_a) as observed:
            turn = target.persist(principal=ACTOR_ATTACKER, session_id=session_a)
            persist_step = step_from_turn(name="persist", actor=ACTOR_ATTACKER, turn=turn)
            steps.append(persist_step)
            _emit(on_step, persist_step)
            view = persist_view(persist_step.response_body)
            if persist_step.error:
                observed.finish(output=view, error=persist_step.error)
                log.end_dialogue()
                return {"steps": steps, "error": persist_step.error, "last_finalize": None}
            observed.finish(output=view)
            log.set_persist(view)
            log.end_dialogue()
        return {
            "steps": steps,
            "error": None,
            "last_finalize": persist_step.response_body,
            "usable_policy": scenario.has_usable_global_policy(persist_step.response_body),
        }

    def trigger(state: AttemptState) -> dict:
        steps = list(state.steps)
        session_b = state.session_b
        user = scenario.trigger or ""
        log.begin_dialogue(name="victim", session_id=session_b)
        with log.stand(user=user, actor="victim", session_id=session_b) as observed:
            turn = target.chat(
                principal=ACTOR_VICTIM,
                session_id=session_b,
                user_content=user,
            )
            trigger_step = step_from_turn(name="trigger", actor=ACTOR_VICTIM, turn=turn)
            steps.append(trigger_step)
            _emit(on_step, trigger_step)
            assistant = _assistant_text(trigger_step.response_body)
            if trigger_step.error:
                observed.finish(output=assistant, error=trigger_step.error)
                log.add_message("user", user)
                log.add_message("assistant", assistant)
                log.end_dialogue()
                return {"steps": steps, "error": trigger_step.error, "success": False}
            observed.finish(output=assistant)
            log.add_message("user", user)
            log.add_message("assistant", assistant)
            log.end_dialogue()
        return {
            "steps": steps,
            "error": None,
            "success": scenario.is_success(assistant),
        }

    def after_adapt(state: AttemptState) -> str:
        return END if state.error else "inject"

    def after_inject(state: AttemptState) -> str:
        if state.error:
            return END
        if scenario.flow != "probe":
            return "persist"
        if state.success or state.injects >= scenario.max_injects:
            return END
        return "adapt"

    def after_persist(state: AttemptState) -> str:
        if state.error:
            return END
        if state.usable_policy or state.injects >= scenario.max_injects:
            return "trigger"
        return "adapt"

    graph = StateGraph(AttemptState)
    graph.add_node("adapt", adapt)
    graph.add_node("inject", inject)
    graph.add_node("persist", persist)
    graph.add_node("trigger", trigger)
    graph.add_edge(START, "adapt")
    graph.add_conditional_edges("adapt", after_adapt)
    graph.add_conditional_edges("inject", after_inject)
    graph.add_conditional_edges("persist", after_persist)
    graph.add_edge("trigger", END)
    return graph.compile()


def run_attempt(
    target: Target,
    scenario: AttackScenario,
    attempt_index: int,
    planner: PayloadPlanner,
    on_step: OnStep | None = None,
    prior_notes: str = "",
    invoke_config: dict | None = None,
    on_graph_tick: Callable[[], None] | None = None,
    dialogue: DialogueTracer | None = None,
    prefix_steps: list[AttackStep] | None = None,
) -> AttemptResult:
    graph = build_attempt_graph(target, scenario, planner, on_step, dialogue)
    initial = {
        "attempt_index": attempt_index,
        "session_a": "",
        "session_b": f"ra-b-{uuid.uuid4().hex[:12]}",
        "injects": 0,
        "payload": "",
        "last_assistant": "",
        "last_finalize": None,
        "prior_notes": prior_notes,
        "steps": list(prefix_steps or []),
        "error": None,
        "usable_policy": False,
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
        session_a=state["session_a"],
        session_b=state["session_b"],
        steps=list(state["steps"]),
    )
