import json

import httpx

from red_alert.attacks import AttackScenario, Flow
from red_alert.profile import StandProfile
from red_alert.profile_target import ProfileTarget
from red_alert.runner import run_attack
from red_alert.target import PRINCIPAL_EVAL, PRINCIPAL_TARGET
from tests.fakes import RecordingSink, ScriptedJudge, ScriptedPlanner

ENV = {"TARGET_TOKEN": "target-secret", "EVAL_TOKEN": "eval-secret", "MODE": "safe"}


def _profile(
    name: str,
    *,
    eval_prompt: str | None = None,
    persist: bool = False,
    reset: bool = True,
) -> StandProfile:
    return StandProfile.model_validate(
        {
            "reset": (
                {
                    "method": "DELETE",
                    "endpoint": "https://agent.test/reset",
                    "bearer_from": "target",
                    "expected_body": {"status": "reset"},
                }
                if reset
                else None
            ),
            "bindings": {
                name: {
                    "target": {
                        "endpoint": "https://agent.test/v1/chat/completions",
                        "bearer_env": "TARGET_TOKEN",
                        "model": "agent-model",
                        "custom_body": {
                            "session_id": "${target_session_id}",
                            "mode": "${MODE}",
                        },
                        "custom_headers": {"X-Agent": "generic"},
                    },
                    "eval": {
                        "inherit": "target",
                        "bearer_env": "EVAL_TOKEN",
                        "prompt": eval_prompt,
                        "custom_body": {"session_id": "${eval_session_id}"},
                    },
                    "persist": (
                        {
                            "method": "POST",
                            "endpoint": "https://agent.test/persist",
                            "bearer_from": "target",
                            "custom_body": {"session_id": "${target_session_id}"},
                            "expected_body": {"ok": True},
                        }
                        if persist
                        else None
                    ),
                }
            },
        }
    )


class AgentMock:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/reset":
            return httpx.Response(200, json={"status": "reset", "extra": True})
        if request.url.path == "/persist":
            return httpx.Response(200, json={"ok": True, "version": 1})
        token = request.headers.get("Authorization")
        text = "evaluated" if token == "Bearer eval-secret" else "target-response"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": text}}]},
        )


def _scenario(name: str, flow: Flow = "probe") -> AttackScenario:
    return AttackScenario(
        name=name,
        flow=flow,
        vulnerability="test",
        goal="test the agent",
        examples=["payload"],
        trigger="verify persisted behavior" if flow == "memory" else None,
        success_check="response proves the behavior",
        max_injects=1,
    )


def test_profile_target_builds_openai_request_from_yaml() -> None:
    mock = AgentMock()
    with mock.client() as client:
        target = ProfileTarget(_profile("probe", eval_prompt="evaluate"), "probe", ENV, client)
        target_turn = target.chat(
            principal=PRINCIPAL_TARGET,
            session_id="target-session",
            user_content="hello",
        )
        eval_turn = target.chat(
            principal=PRINCIPAL_EVAL,
            session_id="eval-session",
            user_content="check",
        )

    assert target_turn.error is None
    assert eval_turn.error is None
    target_request, eval_request = mock.requests
    target_body = json.loads(target_request.content)
    eval_body = json.loads(eval_request.content)
    assert target_request.headers["Authorization"] == "Bearer target-secret"
    assert target_request.headers["X-Agent"] == "generic"
    assert target_body == {
        "session_id": "target-session",
        "mode": "safe",
        "model": "agent-model",
        "messages": [{"role": "user", "content": "hello"}],
    }
    assert eval_request.headers["Authorization"] == "Bearer eval-secret"
    assert eval_body["session_id"] == "eval-session"
    assert eval_body["messages"][0]["content"] == "check"


def test_openclaw_style_profile_needs_no_adapter() -> None:
    profile = StandProfile.model_validate(
        {
            "bindings": {
                "openclaw": {
                    "target": {
                        "endpoint": "https://gateway.test/v1/chat/completions",
                        "bearer_env": "GATEWAY_TOKEN",
                        "model": "openclaw/default",
                    },
                    "eval": {"inherit": "target"},
                    "persist": None,
                }
            }
        }
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        target = ProfileTarget(
            profile,
            "openclaw",
            {"GATEWAY_TOKEN": "gateway-secret"},
            client,
        )
        turn = target.chat(
            principal=PRINCIPAL_TARGET,
            session_id="unused",
            user_content="hello",
        )

    assert turn.error is None
    assert requests[0].headers["Authorization"] == "Bearer gateway-secret"
    assert json.loads(requests[0].content) == {
        "model": "openclaw/default",
        "messages": [{"role": "user", "content": "hello"}],
    }


def test_unknown_framework_uses_custom_endpoint_headers_and_body() -> None:
    profile = StandProfile.model_validate(
        {
            "bindings": {
                "custom": {
                    "target": {
                        "endpoint": "${CUSTOM_URL}",
                        "custom_headers": {"X-API-Key": "${CUSTOM_TOKEN}"},
                        "custom_body": {"thread": "${target_session_id}", "vendor": "other"},
                    },
                    "eval": {"inherit": "target"},
                    "persist": None,
                }
            }
        }
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    environ = {
        "CUSTOM_URL": "https://unknown.test/api/openai/chat",
        "CUSTOM_TOKEN": "custom-secret",
    }
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        target = ProfileTarget(profile, "custom", environ, client)
        target.chat(
            principal=PRINCIPAL_TARGET,
            session_id="thread-1",
            user_content="hello",
        )

    assert requests[0].url == "https://unknown.test/api/openai/chat"
    assert requests[0].headers["X-API-Key"] == "custom-secret"
    assert json.loads(requests[0].content)["thread"] == "thread-1"
    assert target.bearer_values() == ("custom-secret",)


def test_declarative_persist_and_reset_use_methods_and_partial_expected_body() -> None:
    mock = AgentMock()
    with mock.client() as client:
        target = ProfileTarget(_profile("memory", persist=True), "memory", ENV, client)
        reset = target.isolate()
        persisted = target.persist(principal=PRINCIPAL_TARGET, session_id="session-1")

    assert reset is not None and reset.error is None
    assert persisted is not None and persisted.error is None
    assert [(item.method, item.url.path) for item in mock.requests] == [
        ("DELETE", "/reset"),
        ("POST", "/persist"),
    ]
    assert json.loads(mock.requests[1].content) == {"session_id": "session-1"}


def test_probe_without_eval_prompt_judges_target_response_directly() -> None:
    mock = AgentMock()
    judge = ScriptedJudge([True])
    with mock.client() as client:
        report = run_attack(
            profile=_profile("probe"),
            environ=ENV,
            scenario=_scenario("probe"),
            attempts=1,
            http_client=client,
            planner=ScriptedPlanner(["payload"]),
            judge=judge,
        )

    attempt = report.attempts[0]
    assert attempt.success is True
    assert [step.name for step in attempt.steps] == ["isolate", "adapt", "payload", "judge"]
    assert judge.contexts[0].target_response == "target-response"
    assert judge.contexts[0].eval_response is None


def test_probe_eval_prompt_uses_eval_connection_and_both_judge_inputs() -> None:
    mock = AgentMock()
    judge = ScriptedJudge([True])
    with mock.client() as client:
        report = run_attack(
            profile=_profile("probe", eval_prompt="independent check"),
            environ=ENV,
            scenario=_scenario("probe"),
            attempts=1,
            http_client=client,
            planner=ScriptedPlanner(["payload"]),
            judge=judge,
        )

    assert [step.name for step in report.attempts[0].steps] == [
        "isolate",
        "adapt",
        "payload",
        "eval",
        "judge",
    ]
    assert judge.contexts[0].target_response == "target-response"
    assert judge.contexts[0].eval_response == "evaluated"


def test_memory_flow_uses_declarative_persist_then_eval() -> None:
    mock = AgentMock()
    sink = RecordingSink()
    with mock.client() as client:
        report = run_attack(
            profile=_profile("memory", persist=True),
            environ=ENV,
            scenario=_scenario("memory", flow="memory"),
            attempts=1,
            http_client=client,
            planner=ScriptedPlanner(["payload"]),
            judge=ScriptedJudge([True]),
            sink=sink,
        )

    attempt = report.attempts[0]
    assert attempt.success is True
    assert [step.name for step in attempt.steps] == [
        "isolate",
        "adapt",
        "payload",
        "persist",
        "eval",
        "judge",
    ]
    assert attempt.target_session_id.startswith("ra-target-")
    assert attempt.eval_session_id.startswith("ra-eval-")
    assert sink.starts[0]["scenario"] == "memory"


def test_memory_prefers_eval_prompt_over_scenario_trigger() -> None:
    mock = AgentMock()
    with mock.client() as client:
        report = run_attack(
            profile=_profile("memory", persist=True, eval_prompt="independent memory check"),
            environ=ENV,
            scenario=_scenario("memory", flow="memory"),
            attempts=1,
            http_client=client,
            planner=ScriptedPlanner(["payload"]),
            judge=ScriptedJudge([True]),
        )
    eval_request = next(
        request
        for request in mock.requests
        if request.headers.get("Authorization") == "Bearer eval-secret"
    )
    assert json.loads(eval_request.content)["messages"][0]["content"] == (
        "independent memory check"
    )
    assert report.attempts[0].success is True


def test_absent_optional_reset_and_persist_make_no_requests() -> None:
    mock = AgentMock()
    with mock.client() as client:
        report = run_attack(
            profile=_profile("probe", reset=False),
            environ=ENV,
            scenario=_scenario("probe"),
            attempts=1,
            http_client=client,
            planner=ScriptedPlanner(["payload"]),
            judge=ScriptedJudge([True]),
        )
    assert [step.name for step in report.attempts[0].steps] == [
        "adapt",
        "payload",
        "judge",
    ]
    assert all(request.url.path not in {"/reset", "/persist"} for request in mock.requests)
