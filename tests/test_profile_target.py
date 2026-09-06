import json

import httpx
import pytest

from red_alert.config import UsageError
from red_alert.profile import StandProfile
from red_alert.profile_target import ProfileTarget, profile_secret_values
from red_alert.target import PRINCIPAL_EVAL, PRINCIPAL_TARGET


def _profile(binding: dict, *, reset: dict | None = None) -> StandProfile:
    return StandProfile.model_validate({"reset": reset, "bindings": {"probe": binding}})


class Recorder:
    def __init__(self, handler) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))


def _ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})


def test_eval_inherits_target_and_overrides_bearer() -> None:
    profile = _profile(
        {
            "target": {
                "endpoint": "https://agent.test/v1/chat/completions",
                "bearer_env": "TARGET_TOKEN",
                "model": "shared-model",
                "custom_headers": {"X-Shared": "1"},
            },
            "eval": {"inherit": "target", "bearer_env": "EVAL_TOKEN"},
            "persist": None,
        }
    )
    recorder = Recorder(_ok)
    with recorder.client() as client:
        target = ProfileTarget(
            profile,
            "probe",
            {"TARGET_TOKEN": "target-secret", "EVAL_TOKEN": "eval-secret"},
            client,
        )
        target.chat(principal=PRINCIPAL_TARGET, session_id="t1", user_content="hi")
        target.chat(principal=PRINCIPAL_EVAL, session_id="e1", user_content="check")

    assert recorder.requests[0].headers["Authorization"] == "Bearer target-secret"
    assert recorder.requests[1].headers["Authorization"] == "Bearer eval-secret"
    assert recorder.requests[1].headers["X-Shared"] == "1"
    assert json.loads(recorder.requests[1].content)["model"] == "shared-model"


def test_same_user_eval_reuses_target_bearer() -> None:
    profile = _profile(
        {
            "target": {
                "endpoint": "https://agent.test/chat",
                "bearer_env": "SHARED_TOKEN",
            },
            "eval": {"inherit": "target"},
            "persist": None,
        }
    )
    recorder = Recorder(_ok)
    with recorder.client() as client:
        target = ProfileTarget(profile, "probe", {"SHARED_TOKEN": "same-secret"}, client)
        target.chat(principal=PRINCIPAL_TARGET, session_id="t1", user_content="hi")
        target.chat(principal=PRINCIPAL_EVAL, session_id="e1", user_content="check")

    assert {item.headers["Authorization"] for item in recorder.requests} == {"Bearer same-secret"}


def test_placeholders_model_headers_and_body_come_from_env() -> None:
    profile = _profile(
        {
            "target": {
                "endpoint": "${AGENT_URL}",
                "model": "${AGENT_MODEL}",
                "custom_body": {
                    "session_id": "${target_session_id}",
                    "thread": "${eval_session_id}",
                },
                "custom_headers": {"X-API-Key": "${AGENT_TOKEN}"},
            },
            "eval": {"inherit": "target"},
            "persist": None,
        }
    )
    recorder = Recorder(_ok)
    environ = {
        "AGENT_URL": "https://unknown.test/openai/chat",
        "AGENT_MODEL": "vendor-model",
        "AGENT_TOKEN": "header-secret",
    }
    with recorder.client() as client:
        target = ProfileTarget(profile, "probe", environ, client)
        target.chat(principal=PRINCIPAL_TARGET, session_id="session-1", user_content="hi")

    body = json.loads(recorder.requests[0].content)
    assert recorder.requests[0].url == "https://unknown.test/openai/chat"
    assert recorder.requests[0].headers["X-API-Key"] == "header-secret"
    assert body["model"] == "vendor-model"
    assert body["session_id"] == "session-1"
    assert body["thread"] == "session-1"
    assert target.bearer_values() == ("header-secret",)
    assert profile_secret_values(profile, "probe", environ) == ("header-secret",)


def test_missing_bearer_and_placeholder_fail_before_http() -> None:
    profile = _profile(
        {
            "target": {
                "endpoint": "https://agent.test/chat",
                "bearer_env": "TARGET_TOKEN",
            },
            "eval": {"inherit": "target"},
            "persist": None,
        }
    )
    with httpx.Client() as client:
        with pytest.raises(UsageError, match="TARGET_TOKEN"):
            ProfileTarget(profile, "probe", {}, client)

    missing = _profile(
        {
            "target": {"endpoint": "${MISSING_URL}"},
            "eval": {"inherit": "target"},
            "persist": None,
        }
    )
    with httpx.Client() as client:
        with pytest.raises(UsageError, match="MISSING_URL"):
            ProfileTarget(missing, "probe", {}, client)


def test_null_bearer_sends_no_authorization() -> None:
    profile = _profile(
        {
            "target": {"endpoint": "https://public.test/chat", "bearer_env": None},
            "eval": {"inherit": "target"},
            "persist": None,
        }
    )
    recorder = Recorder(_ok)
    with recorder.client() as client:
        ProfileTarget(profile, "probe", {}, client).chat(
            principal=PRINCIPAL_TARGET,
            session_id="s1",
            user_content="hi",
        )
    assert "Authorization" not in recorder.requests[0].headers


def test_persist_and_reset_use_declared_method_and_partial_expected_body() -> None:
    profile = _profile(
        {
            "target": {"endpoint": "https://agent.test/chat", "bearer_env": "TARGET_TOKEN"},
            "eval": {"inherit": "target"},
            "persist": {
                "method": "POST",
                "endpoint": "https://agent.test/sessions/${target_session_id}/finalize",
                "bearer_from": "target",
                "custom_body": {"session_id": "${target_session_id}"},
                "expected_body": {"ok": True},
            },
        },
        reset={
            "method": "DELETE",
            "endpoint": "https://agent.test/reset",
            "bearer_from": "target",
            "expected_body": {"status": "reset"},
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/reset":
            return httpx.Response(200, json={"status": "reset", "extra": True})
        if request.url.path.endswith("/finalize"):
            return httpx.Response(200, json={"ok": True, "version": 7})
        return _ok(request)

    recorder = Recorder(handler)
    with recorder.client() as client:
        target = ProfileTarget(profile, "probe", {"TARGET_TOKEN": "secret"}, client)
        reset = target.isolate()
        persisted = target.persist(principal=PRINCIPAL_TARGET, session_id="abc")

    assert reset is not None and reset.error is None
    assert persisted is not None and persisted.error is None
    assert [(item.method, item.url.path) for item in recorder.requests] == [
        ("DELETE", "/reset"),
        ("POST", "/sessions/abc/finalize"),
    ]


def test_expected_body_mismatch_is_error() -> None:
    profile = _profile(
        {
            "target": {"endpoint": "https://agent.test/chat"},
            "eval": {"inherit": "target"},
            "persist": {
                "method": "POST",
                "endpoint": "https://agent.test/persist",
                "expected_body": {"ok": True},
            },
        }
    )
    recorder = Recorder(lambda _request: httpx.Response(200, json={"ok": False}))
    with recorder.client() as client:
        turn = ProfileTarget(profile, "probe", {}, client).persist(
            principal=PRINCIPAL_TARGET,
            session_id="s1",
        )
    assert turn is not None
    assert turn.error == "ответ не соответствует expected_body"


def test_network_error_does_not_raise() -> None:
    profile = _profile(
        {
            "target": {"endpoint": "https://agent.test/chat"},
            "eval": {"inherit": "target"},
            "persist": None,
        }
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        turn = ProfileTarget(profile, "probe", {}, client).chat(
            principal=PRINCIPAL_TARGET,
            session_id="s1",
            user_content="hi",
        )
    assert turn.response is None
    assert "down" in (turn.error or "")


def test_null_persist_and_reset_are_noop() -> None:
    profile = _profile(
        {
            "target": {"endpoint": "https://agent.test/chat"},
            "eval": {"inherit": "target"},
            "persist": None,
        }
    )
    recorder = Recorder(_ok)
    with recorder.client() as client:
        target = ProfileTarget(profile, "probe", {}, client)
        assert target.persist(principal=PRINCIPAL_TARGET, session_id="s1") is None
        assert target.isolate() is None
    assert recorder.requests == []
