import uuid
from dataclasses import dataclass, field

import httpx
from langgraph.graph import END, START, StateGraph

from red_alert.models import AttackStep, AttemptResult
from red_alert.scenarios.memory_poisoning import MemoryPoisoningScenario
from red_alert.stand_client import StandClient

ACTOR_ATTACKER = "attacker"
ACTOR_VICTIM = "victim"


@dataclass
class AttemptState:
    attempt_index: int
    session_a: str
    session_b: str
    injects: int
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


def _send_payloads(
    attacker: StandClient,
    scenario: MemoryPoisoningScenario,
    session_id: str,
    steps: list[AttackStep],
) -> str | None:
    for index, payload in enumerate(scenario.payloads, start=1):
        step_name = "payload" if len(scenario.payloads) == 1 else f"payload-{index}"
        try:
            request_body, response = attacker.chat(session_id=session_id, user_content=payload)
        except httpx.RequestError as exc:
            steps.append(
                _error_step(
                    name=step_name,
                    method="POST",
                    url=attacker.chat_url(),
                    actor=ACTOR_ATTACKER,
                    request_body={"session_id": session_id},
                    error=str(exc),
                )
            )
            return str(exc)
        payload_step = _http_step(
            name=step_name,
            method="POST",
            url=attacker.chat_url(),
            actor=ACTOR_ATTACKER,
            request_body=request_body,
            response=response,
        )
        steps.append(payload_step)
        if payload_step.error:
            return payload_step.error
    return None


def build_attempt_graph(
    attacker: StandClient,
    victim: StandClient,
    scenario: MemoryPoisoningScenario,
):
    def inject(state: AttemptState) -> dict:
        steps = list(state.steps)
        session_a = f"ra-a-{uuid.uuid4().hex[:12]}"
        error = _send_payloads(attacker, scenario, session_a, steps)
        return {
            "session_a": session_a,
            "injects": state.injects + 1,
            "steps": steps,
            "error": error,
            "usable_policy": False,
        }

    def finalize(state: AttemptState) -> dict:
        steps = list(state.steps)
        session_a = state.session_a
        try:
            _, response = attacker.finalize(session_a)
        except httpx.RequestError as exc:
            steps.append(
                _error_step(
                    name="finalize",
                    method="POST",
                    url=attacker.finalize_url(session_a),
                    actor=ACTOR_ATTACKER,
                    request_body=None,
                    error=str(exc),
                )
            )
            return {"steps": steps, "error": str(exc)}
        finalize_step = _http_step(
            name="finalize",
            method="POST",
            url=attacker.finalize_url(session_a),
            actor=ACTOR_ATTACKER,
            request_body=None,
            response=response,
        )
        steps.append(finalize_step)
        if finalize_step.error:
            return {"steps": steps, "error": finalize_step.error}
        return {
            "steps": steps,
            "error": None,
            "usable_policy": scenario.has_usable_global_policy(finalize_step.response_body),
        }

    def trigger(state: AttemptState) -> dict:
        steps = list(state.steps)
        session_b = state.session_b
        try:
            request_body, response = victim.chat(
                session_id=session_b, user_content=scenario.trigger
            )
        except httpx.RequestError as exc:
            steps.append(
                _error_step(
                    name="trigger",
                    method="POST",
                    url=victim.chat_url(),
                    actor=ACTOR_VICTIM,
                    request_body={"session_id": session_b},
                    error=str(exc),
                )
            )
            return {"steps": steps, "error": str(exc), "success": False}
        trigger_step = _http_step(
            name="trigger",
            method="POST",
            url=victim.chat_url(),
            actor=ACTOR_VICTIM,
            request_body=request_body,
            response=response,
        )
        steps.append(trigger_step)
        if trigger_step.error:
            return {"steps": steps, "error": trigger_step.error, "success": False}
        return {
            "steps": steps,
            "error": None,
            "success": scenario.is_success(_assistant_text(trigger_step.response_body)),
        }

    def after_inject(state: AttemptState) -> str:
        return END if state.error else "finalize"

    def after_finalize(state: AttemptState) -> str:
        if state.error:
            return END
        if state.usable_policy or state.injects >= scenario.max_injects:
            return "trigger"
        return "inject"

    graph = StateGraph(AttemptState)
    graph.add_node("inject", inject)
    graph.add_node("finalize", finalize)
    graph.add_node("trigger", trigger)
    graph.add_edge(START, "inject")
    graph.add_conditional_edges("inject", after_inject)
    graph.add_conditional_edges("finalize", after_finalize)
    graph.add_edge("trigger", END)
    return graph.compile()


def run_attempt(
    attacker: StandClient,
    victim: StandClient,
    scenario: MemoryPoisoningScenario,
    attempt_index: int,
) -> AttemptResult:
    state = build_attempt_graph(attacker, victim, scenario).invoke(
        {
            "attempt_index": attempt_index,
            "session_a": "",
            "session_b": f"ra-b-{uuid.uuid4().hex[:12]}",
            "injects": 0,
            "steps": [],
            "error": None,
            "usable_policy": False,
            "success": False,
        }
    )
    return AttemptResult(
        attempt_index=state["attempt_index"],
        success=bool(state["success"]),
        session_a=state["session_a"],
        session_b=state["session_b"],
        steps=list(state["steps"]),
    )
