from typing import Protocol

import httpx

from red_alert.models import AttackStep

PRINCIPAL_TARGET = "target"
PRINCIPAL_EVAL = "eval"


class ResetError(Exception):
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


UserContent = str | list


class Target(Protocol):
    @property
    def eval_prompt(self) -> str | None: ...

    def chat(self, *, principal: str, session_id: str, user_content: UserContent) -> TargetTurn: ...

    def persist(self, *, principal: str, session_id: str) -> TargetTurn | None: ...

    def isolate(self) -> TargetTurn | None: ...
