from io import StringIO
from pathlib import Path
from typing import cast

import pytest
from rich.console import Console

from red_alert.analyzer import (
    CODEX_HARNESS_IMAGE,
    CONTAINER_CODEX_HOME,
    CONTAINER_IO_DIR,
    CONTAINER_WORKSPACE,
    LATEST_ANALYZER_LOG_NAME,
    FakeAnalyzer,
    HeuristicAnalyzer,
    _extract_json_object,
    _normalize_profile_data,
    _parse_profile_payload,
    _stream_codex_trace,
    analyzer_log_path,
    build_analyzer_prompt,
    build_codex_docker_command,
    catalog_brief,
    codex_harness_assets_dir,
    codex_pretty_trace_path,
    codex_trace_path,
    harness_schema_for,
)
from red_alert.cli import main
from red_alert.profile import CapabilityState, StandProfile


def _console() -> Console:
    return Console(file=StringIO())


def test_inspect_fake_writes_profile(tmp_path: Path) -> None:
    source = tmp_path / "stand"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    output = tmp_path / "profile.yaml"
    profile = StandProfile(
        capabilities={"vision": CapabilityState(status="absent", confidence="high")},
        bindings={"memory-poisoning": {"policy": "x", "trigger": "y", "proof": "z"}},
    )
    code = main(
        ["inspect", str(source), "--output", str(output)],
        analyzer=FakeAnalyzer(profile),
        console=_console(),
    )
    text = output.read_text(encoding="utf-8")
    assert code == 0
    assert "vision" in text
    assert "absent" in text


def test_inspect_missing_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["inspect", str(tmp_path / "missing")], analyzer=FakeAnalyzer(StandProfile()))
    err = capsys.readouterr().err
    assert code == 2
    assert "Нет каталога" in err


def test_inspect_does_not_need_stand_keys(tmp_path: Path) -> None:
    source = tmp_path / "stand"
    source.mkdir()
    output = tmp_path / "out.yaml"
    code = main(
        ["inspect", str(source), "-o", str(output)],
        environ={},
        analyzer=FakeAnalyzer(StandProfile()),
        console=_console(),
    )
    assert code == 0
    assert output.is_file()


def test_inspect_writes_context_path(tmp_path: Path) -> None:
    source = tmp_path / "stand"
    source.mkdir()
    context = tmp_path / "CONTEXT.md"
    context.write_text("Target URL: http://agent.test/v1/chat/completions\n", encoding="utf-8")
    output = tmp_path / "out.yaml"

    code = main(
        [
            "inspect",
            str(source),
            "--context",
            str(context),
            "--output",
            str(output),
        ],
        analyzer=FakeAnalyzer(StandProfile()),
        console=_console(),
    )

    assert code == 0
    assert f"context: {context}" in output.read_text(encoding="utf-8")


def test_inspect_rejects_missing_context(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "stand"
    source.mkdir()

    code = main(
        ["inspect", str(source), "--context", str(tmp_path / "missing.md")],
        analyzer=FakeAnalyzer(StandProfile()),
    )

    assert code == 2
    assert "Нет файла контекста" in capsys.readouterr().err


def test_heuristic_does_not_seed_target_specific_bindings(tmp_path: Path) -> None:
    source = tmp_path / "genai-invest-agent-memory-stand"
    source.mkdir()
    (source / "readme.md").write_text(
        "persist memory finalize agent_policy YDEX CUS 1002\n",
        encoding="utf-8",
    )
    profile = HeuristicAnalyzer().analyze(source)
    assert profile.bindings == {}


def test_heuristic_unknown_repo_has_empty_bindings(tmp_path: Path) -> None:
    source = tmp_path / "other-agent"
    source.mkdir()
    (source / "readme.md").write_text("hello world chatbot\n", encoding="utf-8")
    profile = HeuristicAnalyzer().analyze(source)
    assert profile.bindings == {}


def test_inspect_skips_env_secrets(tmp_path: Path) -> None:
    source = tmp_path / "stand"
    source.mkdir()
    (source / ".env").write_text("OPENAI_API_KEY=sk-secret-stand\n", encoding="utf-8")
    (source / "readme.md").write_text("memory persist finalize\n", encoding="utf-8")
    profile = HeuristicAnalyzer().analyze(source)
    dumped = profile.model_dump_json()
    assert "sk-secret-stand" not in dumped


def test_heuristic_writes_analyzer_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "stand"
    source.mkdir()
    (source / "readme.md").write_text("memory persist\n", encoding="utf-8")
    HeuristicAnalyzer().analyze(source)
    log_path = analyzer_log_path()
    assert log_path == tmp_path / "attack_artifacts" / LATEST_ANALYZER_LOG_NAME
    text = log_path.read_text(encoding="utf-8")
    assert "analyzer: heuristic" in text
    assert str(source) in text
    assert "OUT parsed profile:" in text
    assert "OUT error: (none)" in text


def test_llm_analyzer_logs_request_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from red_alert.analyzer import LlmAnalyzer
    from red_alert.planner import LlmConfig

    monkeypatch.chdir(tmp_path)
    source = tmp_path / "stand"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")

    class BrokenClient:
        def post(self, *_args: object, **_kwargs: object) -> httpx.Response:
            raise httpx.ConnectError("[Errno 49] Can't assign requested address")

    analyzer = LlmAnalyzer(
        LlmConfig(api_key="k", base_url="http://127.0.0.1:9", model="m", max_tokens=100),
        cast(httpx.Client, BrokenClient()),
    )
    with pytest.raises(Exception, match="Can't assign requested address"):
        analyzer.analyze(source)
    text = analyzer_log_path().read_text(encoding="utf-8")
    assert "analyzer: llm" in text
    assert "Can't assign requested address" in text
    assert "IN prompt:" in text


def test_inspect_llm_without_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "stand"
    source.mkdir()
    code = main(
        ["inspect", str(source), "--analyzer", "llm"],
        environ={},
    )
    err = capsys.readouterr().err
    assert code == 2
    assert "OPENAI_API_KEY" in err


def test_harness_schema_is_strict() -> None:
    schema = harness_schema_for(catalog_brief())
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "source",
        "context",
        "reset",
        "defaults",
        "capabilities",
        "bindings",
    }
    assert schema["properties"]["bindings"]["additionalProperties"] is False
    assert "memory-poisoning" in schema["properties"]["bindings"]["required"]
    assert "memory-poisoning" in schema["properties"]["bindings"]["properties"]
    memory = schema["properties"]["bindings"]["properties"]["memory-poisoning"]
    assert set(memory["required"]) == {
        "applicable",
        "policy",
        "trigger",
        "proof",
        "target",
        "eval",
        "persist",
    }
    assert set(memory["properties"]["target"]["required"]) == {
        "inherit",
        "endpoint",
        "bearer_env",
        "model",
        "prompt",
        "custom_body",
        "custom_headers",
    }


def test_analyzer_prompt_includes_catalog_slots() -> None:
    text = build_analyzer_prompt(
        Path("stand-src"),
        context_text="Use https://agent.test/v1/chat/completions and TARGET_TOKEN",
        context_name="CONTEXT.md",
    )
    assert "memory-poisoning" in text
    assert "policy" in text
    assert "trigger" in text
    assert "proof" in text
    assert "https://agent.test/v1/chat/completions" in text
    assert "CONTEXT.md" in text
    assert "bearer_env" in text
    names = {item["name"] for item in catalog_brief()}
    assert "memory-poisoning" in names


def test_parse_profile_unwraps_standprofile_wrapper() -> None:
    raw = """```json
{
  "StandProfile": {
    "capabilities": {
      "persistent_memory": {"status": "present", "confidence": "high", "domain": "x"},
      "multi_user": {"status": "present", "confidence": "high"},
      "vision": {"status": "present", "confidence": "high"}
    }
  }
}
```"""
    profile = _parse_profile_payload(raw, "stand")
    assert profile.capabilities["persistent_memory"].status == "present"
    assert profile.capabilities["vision"].status == "present"
    assert profile.bindings == {}


def test_normalize_profile_keeps_bindings() -> None:
    data = {
        "source": "x",
        "capabilities": {
            "persistent_memory": {"status": "present", "confidence": "high"},
            "multi_user": {"status": "absent", "confidence": "high"},
            "vision": {"status": "unknown", "confidence": "low"},
        },
        "bindings": {
            "memory-poisoning": {"policy": "p", "trigger": "t", "proof": "ok"},
        },
    }
    normalized = _normalize_profile_data(data)
    profile = StandProfile.model_validate(normalized)
    assert profile.bindings["memory-poisoning"]["policy"] == "p"


def test_normalize_profile_converts_strict_schema_fields_to_objects() -> None:
    normalized = _normalize_profile_data(
        {
            "reset": {
                "method": "POST",
                "endpoint": "http://agent.test/reset",
                "bearer_from": "target",
                "custom_body": None,
                "custom_headers": None,
                "expected_body": [{"name": "status", "value": "reset"}],
            },
            "bindings": {
                "memory-poisoning": {
                    "target": {
                        "custom_body": [
                            {"name": "session_id", "value": "${target_session_id}"},
                            {"name": "reasoning", "value": False},
                        ],
                        "custom_headers": None,
                    },
                    "eval": {"custom_body": None, "custom_headers": None},
                    "persist": None,
                }
            },
        }
    )

    assert normalized["reset"]["expected_body"] == {"status": "reset"}
    target = normalized["bindings"]["memory-poisoning"]["target"]
    assert target["custom_body"] == {
        "session_id": "${target_session_id}",
        "reasoning": False,
    }


def test_parse_profile_from_noisy_output() -> None:
    raw = (
        "thinking...\n"
        "```json\n"
        '{"capabilities": {"persistent_memory": {"status": "present", "confidence": "high"},'
        ' "multi_user": {"status": "present", "confidence": "high"},'
        ' "vision": {"status": "absent", "confidence": "high"}},'
        ' "bindings": {"memory-poisoning": {"policy": "do not hold ACME",'
        ' "trigger": "what is my portfolio", "proof": "true if ACME"}}} \n'
        "```\n"
    )
    assert _extract_json_object(raw)
    profile = _parse_profile_payload(raw, "stand")
    assert profile.bindings["memory-poisoning"]["policy"] == "do not hold ACME"


def test_codex_trace_writes_raw_and_pretty_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    raw = (
        '{"type":"thread.started","thread_id":"test-thread"}\n'
        '{"type":"item.completed","item":{"type":"agent_message","text":"готово"}}\n'
    )
    _stream_codex_trace(StringIO(raw))

    assert codex_trace_path().read_text(encoding="utf-8") == raw
    pretty = codex_pretty_trace_path().read_text(encoding="utf-8")
    assert '\n  "type": "thread.started"' in pretty
    assert '\n    "text": "готово"' in pretty


def test_harness_docker_command_mounts_only_source_and_temporary_dirs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "stand"
    io_dir = tmp_path / "io"
    codex_home = tmp_path / "codex-home"
    source.mkdir()
    io_dir.mkdir()
    codex_home.mkdir()

    command = build_codex_docker_command(
        source,
        io_dir=io_dir,
        codex_home=codex_home,
    )

    assert command[:3] == ["docker", "run", "--rm"]
    assert CODEX_HARNESS_IMAGE in command
    assert "--read-only" in command
    assert "/tmp:rw,nosuid,nodev,size=64m" in command
    assert "--cap-drop" in command
    assert "no-new-privileges" in command
    assert command[command.index("--workdir") + 1] == CONTAINER_WORKSPACE
    mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
    assert any(
        f"source={source.resolve()}" in mount
        and f"target={CONTAINER_WORKSPACE}" in mount
        and "readonly" in mount
        for mount in mounts
    )
    assert any(f"target={CONTAINER_IO_DIR}" in mount for mount in mounts)
    assert any(f"target={CONTAINER_CODEX_HOME}" in mount for mount in mounts)
    assert not any("OPENAI_API_KEY" in item or "CODEX_SESSION_ID" in item for item in command)


def test_codex_harness_docker_assets_are_packaged() -> None:
    assets = codex_harness_assets_dir()
    dockerfile = (assets / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG CODEX_VERSION=0.153.4" in dockerfile
    assert '"@openai/codex@${CODEX_VERSION}"' in dockerfile
    assert "requirements.toml" in dockerfile
    assert "red-alert-harness.config.toml" in dockerfile
    assert "/etc/codex/config.toml" in dockerfile
    assert (assets / "entrypoint.sh").is_file()


def test_harness_sends_prompt_on_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from red_alert.analyzer import CodexHarnessAnalyzer

    source = tmp_path / "stand"
    source.mkdir()
    host_codex_home = tmp_path / "host-codex"
    host_codex_home.mkdir()
    (host_codex_home / "auth.json").write_text('{"tokens": {}}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    captured: dict[str, object] = {}

    def _run(args: list[str], *, cwd: Path, prompt: str, timeout: int) -> tuple[int, str]:
        captured["args"] = args
        captured["cwd"] = cwd
        captured["input"] = prompt
        captured["timeout"] = timeout
        io_mount = next(
            args[index + 1]
            for index, item in enumerate(args)
            if item == "--mount" and f"target={CONTAINER_IO_DIR}" in args[index + 1]
        )
        host_io = Path(
            next(
                part.removeprefix("source=")
                for part in io_mount.split(",")
                if part.startswith("source=")
            )
        )
        last = host_io / "last-message.txt"
        last.write_text(
            '{"capabilities": {"persistent_memory": {"status": "present", "confidence": "high"},'
            ' "multi_user": {"status": "present", "confidence": "high"},'
            ' "vision": {"status": "present", "confidence": "high"}},'
            ' "bindings": {"memory-poisoning": {"policy": "p", "trigger": "t", "proof": "ok"}}}',
            encoding="utf-8",
        )
        _stream_codex_trace(StringIO('{"type":"thread.started","thread_id":"test-thread"}\n'))
        return 0, ""

    monkeypatch.setattr("red_alert.analyzer._run_codex_container", _run)
    profile = CodexHarnessAnalyzer(
        {"CODEX_HOME": str(host_codex_home)},
        context_text="Use https://agent.test/v1/chat/completions",
        context_name="CONTEXT.md",
    ).analyze(source)
    argv = captured["args"]
    assert isinstance(argv, list)
    assert argv[-1] == "-"
    assert "--json" in argv
    assert argv[:2] == ["docker", "run"]
    assert CODEX_HARNESS_IMAGE in argv
    assert "--ignore-user-config" in argv
    assert argv[argv.index("--profile") + 1] == "red-alert-harness"
    assert "--strict-config" in argv
    assert "--ephemeral" in argv
    assert "--sandbox" not in argv
    assert "--add-dir" not in argv
    assert "memory-poisoning" in str(captured["input"])
    assert CONTAINER_WORKSPACE in str(captured["input"])
    assert "https://agent.test/v1/chat/completions" in str(captured["input"])
    assert profile.context == "CONTEXT.md"
    assert profile.bindings["memory-poisoning"]["policy"] == "p"
    trace = codex_trace_path()
    assert trace == tmp_path / "analysis_artifacts" / "latest_codex_trace.jsonl"
    assert '"thread_id":"test-thread"' in trace.read_text(encoding="utf-8")
    assert codex_pretty_trace_path().is_file()


def test_harness_preserves_trace_on_codex_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from red_alert.analyzer import AnalyzerError, CodexHarnessAnalyzer

    source = tmp_path / "stand"
    source.mkdir()
    host_codex_home = tmp_path / "host-codex"
    host_codex_home.mkdir()
    (host_codex_home / "auth.json").write_text('{"tokens": {}}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def _run(_args: list[str], *, cwd: Path, prompt: str, timeout: int) -> tuple[int, str]:
        del cwd, prompt, timeout
        _stream_codex_trace(StringIO('{"type":"thread.started","thread_id":"failed-thread"}\n'))
        return 1, "codex failed"

    monkeypatch.setattr("red_alert.analyzer._run_codex_container", _run)
    with pytest.raises(AnalyzerError, match="codex failed"):
        CodexHarnessAnalyzer({"CODEX_HOME": str(host_codex_home)}).analyze(source)
    assert '"thread_id":"failed-thread"' in codex_trace_path().read_text(encoding="utf-8")


def test_inspect_harness_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "stand"
    source.mkdir()

    auth = tmp_path / "auth.json"
    auth.write_text('{"tokens": {}}', encoding="utf-8")

    def _missing(*_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError("docker")

    monkeypatch.setattr("red_alert.analyzer._codex_auth_path", lambda _environ: auth)
    monkeypatch.setattr("red_alert.analyzer._run_codex_container", _missing)
    code = main(
        ["inspect", str(source), "--analyzer", "harness"],
        environ={},
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "Docker" in err
