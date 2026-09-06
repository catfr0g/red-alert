from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

from red_alert.config import UsageError
from red_alert.profile import (
    PLACEHOLDER_RE,
    BindingRuntime,
    ConnectionSpec,
    OperationSpec,
    StandProfile,
    render_runtime_value,
)
from red_alert.target import PRINCIPAL_EVAL, PRINCIPAL_TARGET, TargetTurn, UserContent


def _placeholder_names(value: Any) -> set[str]:
    if isinstance(value, str):
        return {match.group(1) for match in PLACEHOLDER_RE.finditer(value)}
    if isinstance(value, list):
        return set().union(*(_placeholder_names(item) for item in value), set())
    if isinstance(value, dict):
        return set().union(*(_placeholder_names(item) for item in value.values()), set())
    return set()


_SESSION_PLACEHOLDERS = frozenset({"target_session_id", "eval_session_id"})


def profile_secret_values(
    profile: StandProfile,
    binding_name: str,
    environ: Mapping[str, str],
) -> tuple[str, ...]:
    runtime = profile.runtime(binding_name)
    names = {item.bearer_env for item in (runtime.target, runtime.eval) if item.bearer_env}
    blobs: list[Any] = [
        runtime.target.custom_headers,
        runtime.eval.custom_headers,
    ]
    for operation in (runtime.persist, profile.reset):
        if operation is None:
            continue
        blobs.append(operation.custom_headers)
    names.update(_placeholder_names(blobs) - _SESSION_PLACEHOLDERS)
    return tuple(dict.fromkeys(environ[name] for name in sorted(names) if environ.get(name)))


def _valid_url(value: str, label: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise UsageError(f"{label}: нужен полный HTTP(S) endpoint")
    return value


def _partial_match(actual: object, expected: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _partial_match(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(_partial_match(item, wanted) for item, wanted in zip(actual, expected))
        )
    return actual == expected


class ProfileTarget:
    def __init__(
        self,
        profile: StandProfile,
        binding_name: str,
        environ: Mapping[str, str],
        client: httpx.Client,
    ) -> None:
        self.profile = profile
        self.binding_name = binding_name
        self.runtime: BindingRuntime = profile.runtime(binding_name)
        self._environ = environ
        self._client = client
        self._sessions = {"target_session_id": "", "eval_session_id": ""}
        self._validate_static()

    @property
    def eval_prompt(self) -> str | None:
        return self.runtime.eval.prompt

    @property
    def target_endpoint(self) -> str:
        endpoint = self.runtime.target.endpoint
        if not endpoint:
            raise UsageError(f"{self.binding_name}: target.endpoint не задан")
        return endpoint

    def bearer_values(self) -> tuple[str, ...]:
        return profile_secret_values(self.profile, self.binding_name, self._environ)

    def _validate_static(self) -> None:
        if not self.runtime.target.endpoint:
            raise UsageError(f"{self.binding_name}: target.endpoint не задан")
        for label, connection in (
            ("target", self.runtime.target),
            ("eval", self.runtime.eval),
        ):
            if connection.endpoint:
                rendered = self._render(
                    connection.endpoint,
                    principal=label,
                    session_id="validation",
                )
                _valid_url(rendered, f"{self.binding_name}.{label}.endpoint")
            if connection.bearer_env and not self._environ.get(connection.bearer_env):
                raise UsageError(
                    f"{self.binding_name}.{label}: не задана env {connection.bearer_env}"
                )
        for label, operation in (
            ("persist", self.runtime.persist),
            ("reset", self.profile.reset),
        ):
            if operation is None:
                continue
            if not operation.method or not operation.endpoint:
                raise UsageError(f"{self.binding_name}.{label}: нужны method и endpoint")
            rendered = self._render(
                operation.endpoint,
                principal=PRINCIPAL_TARGET,
                session_id="validation",
            )
            _valid_url(rendered, f"{self.binding_name}.{label}.endpoint")
            if operation.bearer_from is None:
                continue
            self._connection(operation.bearer_from)

    def _connection(self, principal: str) -> ConnectionSpec:
        if principal == PRINCIPAL_TARGET:
            return self.runtime.target
        if principal == PRINCIPAL_EVAL:
            return self.runtime.eval
        raise UsageError(f"Неизвестный principal: {principal}")

    def _remember(self, principal: str, session_id: str) -> None:
        if not session_id:
            return
        if principal == PRINCIPAL_TARGET:
            self._sessions["target_session_id"] = session_id
        elif principal == PRINCIPAL_EVAL:
            self._sessions["eval_session_id"] = session_id

    def _builtins(self, principal: str, session_id: str) -> dict[str, str]:
        target_id = (
            session_id if principal == PRINCIPAL_TARGET else self._sessions["target_session_id"]
        )
        eval_id = session_id if principal == PRINCIPAL_EVAL else self._sessions["eval_session_id"]
        return {
            "target_session_id": target_id or session_id,
            "eval_session_id": eval_id or session_id,
        }

    def _render(
        self,
        value: Any,
        *,
        principal: str,
        session_id: str,
    ) -> Any:
        return render_runtime_value(
            value,
            builtins=self._builtins(principal, session_id),
            environ=self._environ,
        )

    def _headers(
        self,
        connection: ConnectionSpec,
        *,
        principal: str,
        session_id: str,
        custom_headers: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        raw = {**(connection.custom_headers or {}), **(custom_headers or {})}
        rendered = self._render(raw, principal=principal, session_id=session_id)
        headers = {"Content-Type": "application/json"}
        for name, value in rendered.items():
            if value is not None:
                headers[str(name)] = str(value)
        if connection.bearer_env:
            headers["Authorization"] = f"Bearer {self._environ[connection.bearer_env]}"
        return headers

    def chat(
        self,
        *,
        principal: str,
        session_id: str,
        user_content: UserContent,
    ) -> TargetTurn:
        connection = self._connection(principal)
        if not connection.endpoint:
            return TargetTurn(
                method="POST",
                url="",
                request_body=None,
                error=f"{principal}.endpoint не задан",
            )
        url = _valid_url(
            self._render(
                connection.endpoint,
                principal=principal,
                session_id=session_id,
            ),
            f"{self.binding_name}.{principal}.endpoint",
        )
        body = self._render(
            connection.custom_body or {},
            principal=principal,
            session_id=session_id,
        )
        if connection.model is not None:
            body["model"] = self._render(
                connection.model,
                principal=principal,
                session_id=session_id,
            )
        body["messages"] = [{"role": "user", "content": user_content}]
        headers = self._headers(
            connection,
            principal=principal,
            session_id=session_id,
        )
        try:
            response = self._client.post(url, json=body, headers=headers)
        except httpx.RequestError as exc:
            return TargetTurn(
                method="POST",
                url=url,
                request_body=body,
                error=str(exc),
            )
        self._remember(principal, session_id)
        return TargetTurn(
            method="POST",
            url=url,
            request_body=body,
            response=response,
        )

    def _operation(
        self,
        operation: OperationSpec,
        *,
        default_principal: str,
        session_id: str,
    ) -> TargetTurn:
        connection = self._connection(operation.bearer_from or default_principal)
        method = operation.method or ""
        endpoint = operation.endpoint or ""
        url = _valid_url(
            self._render(
                endpoint,
                principal=default_principal,
                session_id=session_id,
            ),
            f"{self.binding_name}.{method}.endpoint",
        )
        body = self._render(
            operation.custom_body,
            principal=default_principal,
            session_id=session_id,
        )
        headers = self._headers(
            connection,
            principal=default_principal,
            session_id=session_id,
            custom_headers=operation.custom_headers,
        )
        try:
            response = self._client.request(
                method,
                url,
                json=body,
                headers=headers,
            )
        except httpx.RequestError as exc:
            return TargetTurn(method=method, url=url, request_body=body, error=str(exc))
        self._remember(default_principal, session_id)
        error = None
        if response.is_success and operation.expected_body is not None:
            try:
                actual = response.json()
            except ValueError:
                actual = response.text
            if not _partial_match(actual, operation.expected_body):
                error = "ответ не соответствует expected_body"
        return TargetTurn(
            method=method,
            url=url,
            request_body=body,
            response=response,
            error=error,
        )

    def persist(self, *, principal: str, session_id: str) -> TargetTurn | None:
        if self.runtime.persist is None:
            return None
        return self._operation(
            self.runtime.persist,
            default_principal=principal,
            session_id=session_id,
        )

    def isolate(self) -> TargetTurn | None:
        if self.profile.reset is None:
            return None
        return self._operation(
            self.profile.reset,
            default_principal=PRINCIPAL_TARGET,
            session_id="",
        )
