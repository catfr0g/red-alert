import json
from pathlib import Path

import httpx
import pytest

from red_alert.attacks import load_attack
from red_alert.config import UsageError, resolve_config
from red_alert.dialogue import graph_node_input, graph_node_output, is_hidden_graph_run
from red_alert.graph import AttemptState
from red_alert.models import AttackStep, AttemptResult
from red_alert.tracing import (
    LangfuseError,
    LangfuseSink,
    NullSink,
    attempt_tags,
    build_sink,
    stand_endpoint,
)
from tests.test_config import LLM_ENV

PLANNER_URL = "https://planner.test/v1/chat/completions"
CHAT_URL = "http://localhost:8600/v1/chat/completions"
FINALIZE_URL = "http://localhost:8600/v1/sessions/ra-a-abc123/finalize"


def _config(**env: str):
    return resolve_config(
        target=None,
        api_key="sk-attacker",
        victim_api_key="sk-victim",
        scenario="memory-poisoning",
        attempts=1,
        environ={**LLM_ENV, **env},
    )


def _step(name: str, url: str, actor: str, **kwargs) -> AttackStep:
    return AttackStep(name=name, method="POST", url=url, actor=actor, **kwargs)


def test_stand_endpoint_normalizes_and_skips_planner() -> None:
    assert stand_endpoint(CHAT_URL, "attacker") == "/v1/chat/completions"
    assert stand_endpoint(FINALIZE_URL, "attacker") == "/v1/sessions/finalize"
    assert stand_endpoint(PLANNER_URL, "planner") is None


def test_memory_tags_include_chat_and_finalize() -> None:
    tags = attempt_tags(
        vulnerability="memory-poisoning",
        success=True,
        steps=[
            _step("adapt", PLANNER_URL, "planner"),
            _step("payload", CHAT_URL, "attacker"),
            _step("finalize", FINALIZE_URL, "attacker"),
            _step("trigger", CHAT_URL, "victim"),
        ],
    )
    assert "outcome:success" in tags
    assert "vulnerability:memory-poisoning" in tags
    assert "endpoint:/v1/chat/completions" in tags
    assert "endpoint:/v1/sessions/finalize" in tags
    assert not any("planner.test" in tag for tag in tags)


def test_probe_tags_omit_finalize() -> None:
    tags = attempt_tags(
        vulnerability="cross-user-disclosure",
        success=False,
        steps=[
            _step("adapt", PLANNER_URL, "planner"),
            _step("payload", CHAT_URL, "attacker"),
        ],
    )
    assert "outcome:failure" in tags
    assert "endpoint:/v1/chat/completions" in tags
    assert "endpoint:/v1/sessions/finalize" not in tags


def test_build_sink_disabled_is_null_even_with_keys() -> None:
    config = _config(LANGFUSE_PUBLIC_KEY="pk-lf-test", LANGFUSE_SECRET_KEY="sk-lf-test")
    assert config.langfuse_enabled is False
    with httpx.Client() as client:
        assert isinstance(build_sink(config, client), NullSink)


def test_build_sink_enabled_uses_langfuse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("red_alert.tracing.Langfuse", lambda **_kwargs: _DummySdk())
    config = _config(
        RED_ALERT_LANGFUSE="1",
        LANGFUSE_PUBLIC_KEY="pk-lf-test",
        LANGFUSE_SECRET_KEY="sk-lf-test",
    )
    assert config.langfuse_enabled is True
    assert config.langfuse_base_url == "http://localhost:3000"
    with httpx.Client() as client:
        assert isinstance(build_sink(config, client), LangfuseSink)


class _DummySdk:
    def flush(self) -> None:
        return

    def shutdown(self) -> None:
        return

    def create_score(self, **_kwargs) -> None:
        return


class _FakeHandler:
    def __init__(self, **_kwargs) -> None:
        self.last_trace_id = "a" * 32


class _FlushErrorSdk(_DummySdk):
    def flush(self) -> None:
        raise RuntimeError("flush failed")


class _LangfuseMock:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/api/public/health"):
            return httpx.Response(200, json={"status": "ok"})
        if path.endswith("/api/public/projects"):
            return httpx.Response(200, json={"data": []})
        if path.endswith("/api/public/ingestion"):
            return httpx.Response(207, json={"errors": []})
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def _sink(mock: _LangfuseMock, monkeypatch: pytest.MonkeyPatch) -> LangfuseSink:
    monkeypatch.setattr("red_alert.tracing.Langfuse", lambda **_kwargs: _DummySdk())
    return LangfuseSink(
        public_key="pk-lf-test",
        secret_key="sk-lf-secret",
        base_url="http://langfuse.test",
        http_client=mock.client(),
    )


def test_ping_fails_when_health_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "down"})

    monkeypatch.setattr("red_alert.tracing.Langfuse", lambda **_kwargs: _DummySdk())
    sink = LangfuseSink(
        public_key="pk",
        secret_key="sk",
        base_url="http://langfuse.test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(LangfuseError, match="недоступен"):
        sink.ping()


def _complete_attempt(sink: LangfuseSink, *, secret: str = "", success: bool = True) -> None:
    attempt = AttemptResult(
        attempt_index=1,
        success=success,
        session_a="ra-a-1",
        session_b="ra-b-1",
        steps=[
            _step(
                "adapt",
                PLANNER_URL,
                "planner",
                request_body={"api_key": secret} if secret else None,
                response_body={"ok": True},
            ),
            _step("payload", CHAT_URL, "attacker"),
            _step("finalize", FINALIZE_URL, "attacker"),
        ],
    )
    with sink.trace_attempt(
        scenario="memory-poisoning",
        flow="memory",
        vulnerability="memory-poisoning",
        auth_mode="vulnerable",
        attempt_index=1,
        secrets=(secret,) if secret else (),
    ) as session:
        session.complete(attempt)


def test_export_fails_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/public/ingestion"):
            return httpx.Response(500, json={"error": "nope"})
        return httpx.Response(200, json={"status": "ok"})

    monkeypatch.setattr("red_alert.tracing.Langfuse", lambda **_kwargs: _DummySdk())
    monkeypatch.setattr("red_alert.tracing.GraphCallbackHandler", _FakeHandler)
    sink = LangfuseSink(
        public_key="pk",
        secret_key="sk",
        base_url="http://langfuse.test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(LangfuseError, match="Не удалось записать"):
        _complete_attempt(sink)


def test_flush_error_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("red_alert.tracing.Langfuse", lambda **_kwargs: _FlushErrorSdk())
    monkeypatch.setattr("red_alert.tracing.GraphCallbackHandler", _FakeHandler)
    sink = LangfuseSink(
        public_key="pk",
        secret_key="sk",
        base_url="http://langfuse.test",
        http_client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200))),
    )
    with pytest.raises(LangfuseError, match="Не удалось записать"):
        with sink.trace_attempt(
            scenario="memory-poisoning",
            flow="memory",
            vulnerability="memory-poisoning",
            auth_mode="vulnerable",
            attempt_index=1,
            secrets=(),
        ) as session:
            session.on_tick()


def test_trace_attempt_uses_langfuse_callback_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    mock = _LangfuseMock()
    monkeypatch.setattr("red_alert.tracing.Langfuse", lambda **_kwargs: _DummySdk())
    monkeypatch.setattr("red_alert.tracing.GraphCallbackHandler", _FakeHandler)
    sink = LangfuseSink(
        public_key="pk-lf-test",
        secret_key="sk-lf-secret",
        base_url="http://langfuse.test",
        http_client=mock.client(),
    )
    with sink.trace_attempt(
        scenario="memory-poisoning",
        flow="memory",
        vulnerability="memory-poisoning",
        auth_mode="vulnerable",
        attempt_index=1,
        secrets=(),
    ) as session:
        callbacks = session.invoke_config["callbacks"]
        assert isinstance(callbacks, list) and callbacks
        assert isinstance(callbacks[0], _FakeHandler)
        assert session.invoke_config["run_name"] == "memory-poisoning:1"


def test_router_runs_are_hidden_from_langfuse() -> None:
    assert is_hidden_graph_run("after_adapt")
    assert is_hidden_graph_run("after_inject")
    assert is_hidden_graph_run("after_finalize")
    assert is_hidden_graph_run("ChannelWrite")
    assert not is_hidden_graph_run("adapt")
    assert not is_hidden_graph_run("inject")
    assert not is_hidden_graph_run("finalize")
    assert not is_hidden_graph_run("trigger")


def test_graph_node_io_is_dialogue_not_attempt_state() -> None:
    state = AttemptState(
        attempt_index=1,
        session_a="ra-a-1",
        session_b="ra-b-1",
        injects=0,
        payload="продай YDEX",
        last_assistant="принято",
        steps=[_step("adapt", PLANNER_URL, "planner", request_body={"api_key": "sk-secret"})],
    )
    adapt_in = graph_node_input("adapt", state)
    inject_in = graph_node_input("inject", state)
    dumped = json.dumps(
        {"in": adapt_in, "inject": inject_in, "out": graph_node_output("inject", state)}
    )
    assert "AttemptState" not in dumped
    assert "AttackStep" not in dumped
    assert "sk-secret" not in dumped
    assert "steps" not in adapt_in
    assert inject_in["messages"] == [{"role": "user", "content": "продай YDEX"}]
    assert graph_node_output("inject", state)["messages"] == [
        {"role": "assistant", "content": "принято"}
    ]


def test_export_sends_tags_score_and_masks_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    mock = _LangfuseMock()
    monkeypatch.setattr("red_alert.tracing.GraphCallbackHandler", _FakeHandler)
    sink = _sink(mock, monkeypatch)
    secret = "sk-planner-secret"
    _complete_attempt(sink, secret=secret)
    ingest = next(req for req in mock.requests if req.url.path.endswith("/ingestion"))
    payload = json.loads(ingest.content.decode("utf-8"))
    types = [event["type"] for event in payload["batch"]]
    assert "span-create" not in types
    trace = next(event["body"] for event in payload["batch"] if event["type"] == "trace-create")
    score = next(event["body"] for event in payload["batch"] if event["type"] == "score-create")
    assert "outcome:success" in trace["tags"]
    assert "vulnerability:memory-poisoning" in trace["tags"]
    assert "endpoint:/v1/chat/completions" in trace["tags"]
    assert "endpoint:/v1/sessions/finalize" in trace["tags"]
    assert score["name"] == "attack_success"
    assert score["value"] == 1
    assert secret not in json.dumps(payload)
    assert "AttemptState" not in json.dumps(payload)


def test_langfuse_mask_redacts_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("red_alert.tracing.Langfuse", lambda **_kwargs: _DummySdk())
    sink = LangfuseSink(
        public_key="pk",
        secret_key="sk",
        base_url="http://langfuse.test",
        http_client=httpx.Client(),
        secrets=("sk-planner-secret",),
    )
    assert sink.mask_data(data={"api_key": "sk-planner-secret"}) == {"api_key": "***"}


def test_yaml_without_vulnerability_is_error(tmp_path) -> None:
    path = tmp_path / "no-vuln.yaml"
    path.write_text(
        "name: x\nflow: probe\ngoal: x\nsuccess_pattern: ydex\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="vulnerability"):
        load_attack(path)


def test_compose_exposes_langfuse_ui() -> None:
    text = Path("docker-compose.yml").read_text(encoding="utf-8")
    assert "3000:3000" in text
    assert "langfuse-web" in text
