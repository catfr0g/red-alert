from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from red_alert.analyzer import (
    FakeAnalyzer,
    HeuristicAnalyzer,
    _extract_json_object,
    _parse_profile_payload,
    build_analyzer_prompt,
    catalog_brief,
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


def test_heuristic_seeds_invest_bindings(tmp_path: Path) -> None:
    source = tmp_path / "genai-invest-agent-memory-stand"
    source.mkdir()
    (source / "readme.md").write_text(
        "persist memory finalize agent_policy YDEX CUS 1002\n",
        encoding="utf-8",
    )
    profile = HeuristicAnalyzer().analyze(source)
    assert profile.bindings["memory-poisoning"]["policy"]
    assert "YDEX" in profile.bindings["memory-poisoning"]["proof"]


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
    assert set(schema["required"]) == {"source", "capabilities", "bindings"}
    assert schema["properties"]["bindings"]["additionalProperties"] is False
    assert "memory-poisoning" in schema["properties"]["bindings"]["required"]
    assert "memory-poisoning" in schema["properties"]["bindings"]["properties"]
    memory = schema["properties"]["bindings"]["properties"]["memory-poisoning"]
    assert set(memory["required"]) == {"policy", "trigger", "proof"}


def test_analyzer_prompt_includes_catalog_slots() -> None:
    text = build_analyzer_prompt(Path("stand-src"))
    assert "memory-poisoning" in text
    assert "policy" in text
    assert "trigger" in text
    assert "proof" in text
    names = {item["name"] for item in catalog_brief()}
    assert "memory-poisoning" in names


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


def test_harness_sends_utf8_prompt_on_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from red_alert.analyzer import CodexHarnessAnalyzer

    source = tmp_path / "stand"
    source.mkdir()
    captured: dict[str, object] = {}

    def _run(args: list[str], **kwargs: object) -> object:
        captured["args"] = args
        captured["input"] = kwargs.get("input")
        captured["encoding"] = kwargs.get("encoding")
        last = Path(args[args.index("--output-last-message") + 1])
        last.write_text(
            '{"capabilities": {"persistent_memory": {"status": "present", "confidence": "high"},'
            ' "multi_user": {"status": "present", "confidence": "high"},'
            ' "vision": {"status": "present", "confidence": "high"}},'
            ' "bindings": {"memory-poisoning": {"policy": "p", "trigger": "t", "proof": "ok"}}}',
            encoding="utf-8",
        )

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    monkeypatch.setattr("red_alert.analyzer.subprocess.run", _run)
    profile = CodexHarnessAnalyzer().analyze(source)
    assert captured["encoding"] == "utf-8"
    argv = captured["args"]
    assert isinstance(argv, list)
    assert argv[-1] == "-"
    assert "memory-poisoning" in str(captured["input"])
    assert profile.bindings["memory-poisoning"]["policy"] == "p"


def test_inspect_harness_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "stand"
    source.mkdir()

    def _missing(*_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError("codex")

    monkeypatch.setattr("red_alert.analyzer.subprocess.run", _missing)
    code = main(
        ["inspect", str(source), "--analyzer", "harness"],
        environ={},
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "Codex" in err
