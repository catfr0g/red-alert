import uuid

import httpx

from red_alert.models import AttackStep, AttemptResult, RunReport
from red_alert.scenarios.memory_poisoning import MemoryPoisoningScenario
from red_alert.stand_client import StandClient

ACTOR_ATTACKER = "attacker"
ACTOR_VICTIM = "victim"


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


def _failed(
    *,
    attempt_index: int,
    session_a: str,
    session_b: str,
    steps: list[AttackStep],
) -> AttemptResult:
    return AttemptResult(
        attempt_index=attempt_index,
        success=False,
        session_a=session_a,
        session_b=session_b,
        steps=steps,
    )


def _send_payloads(
    attacker: StandClient,
    scenario: MemoryPoisoningScenario,
    session_id: str,
    steps: list[AttackStep],
) -> str | None:
    """Return an error description if the chain should stop, otherwise None."""
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


def run_attempt(
    attacker: StandClient,
    victim: StandClient,
    scenario: MemoryPoisoningScenario,
    attempt_index: int,
) -> AttemptResult:
    session_a = ""
    session_b = f"ra-b-{uuid.uuid4().hex[:12]}"
    steps: list[AttackStep] = []

    for _ in range(scenario.max_injects):
        session_a = f"ra-a-{uuid.uuid4().hex[:12]}"
        payload_error = _send_payloads(attacker, scenario, session_a, steps)
        if payload_error:
            return _failed(
                attempt_index=attempt_index,
                session_a=session_a,
                session_b=session_b,
                steps=steps,
            )

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
            return _failed(
                attempt_index=attempt_index,
                session_a=session_a,
                session_b=session_b,
                steps=steps,
            )

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
            return _failed(
                attempt_index=attempt_index,
                session_a=session_a,
                session_b=session_b,
                steps=steps,
            )
        if scenario.has_usable_global_policy(finalize_step.response_body):
            break

    try:
        request_body, response = victim.chat(session_id=session_b, user_content=scenario.trigger)
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
        return _failed(
            attempt_index=attempt_index,
            session_a=session_a,
            session_b=session_b,
            steps=steps,
        )

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
        return _failed(
            attempt_index=attempt_index,
            session_a=session_a,
            session_b=session_b,
            steps=steps,
        )

    success = scenario.is_success(_assistant_text(trigger_step.response_body))
    return AttemptResult(
        attempt_index=attempt_index,
        success=success,
        session_a=session_a,
        session_b=session_b,
        steps=steps,
    )


def run_attack(
    *,
    target: str,
    api_key: str,
    victim_api_key: str,
    scenario_name: str,
    attempts: int,
    http_client: httpx.Client,
) -> RunReport:
    if scenario_name != "memory-poisoning":
        raise ValueError(f"Неизвестный сценарий: {scenario_name}")
    scenario = MemoryPoisoningScenario()
    attacker = StandClient(target, api_key, http_client)
    victim = StandClient(target, victim_api_key, http_client)
    results = [run_attempt(attacker, victim, scenario, index) for index in range(1, attempts + 1)]
    return RunReport(scenario=scenario.name, target=target, attempts=results)
