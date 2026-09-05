from typing import Protocol

import httpx

from red_alert.models import AttackStep

PRINCIPAL_ATTACKER = "attacker"
PRINCIPAL_VICTIM = "victim"


class IsolateError(Exception):
    """Isolation failed; the attempt must not enter ASR."""

    def __init__(self, message: str, step: AttackStep | None = None) -> None:
        super().__init__(message)
        self.step = step


class TargetTurn:
    def __init__(
        self,
        *,
        method: str,
        url: str,
        request_body: dict | None,
        response: httpx.Response | None = None,
        error: str | None = None,
    ) -> None:
        self.method = method
        self.url = url
        self.request_body = request_body
        self.response = response
        self.error = error


class Target(Protocol):
    def chat(self, *, principal: str, session_id: str, user_content: str) -> TargetTurn: ...

    def persist(self, *, principal: str, session_id: str) -> TargetTurn: ...

    def isolate(self) -> TargetTurn: ...


def isolate_error(response: httpx.Response) -> str | None:
    if not response.is_success:
        return f"HTTP {response.status_code}"
    try:
        body = response.json()
    except ValueError:
        return "ответ без status=reset"
    if not isinstance(body, dict) or body.get("status") != "reset":
        return "ответ без status=reset"
    return None
