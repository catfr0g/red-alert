from pathlib import Path

from red_alert.config import normalize_target, read_env_file, resolve_config


def test_normalize_target_strips_chat_path() -> None:
    assert normalize_target("http://localhost:8600/v1/chat/completions") == "http://localhost:8600"


def test_normalize_target_keeps_base_url() -> None:
    assert normalize_target("http://localhost:8600/") == "http://localhost:8600"


def test_read_env_file_skips_comments(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "# comment\nRED_ALERT_TARGET=http://stand:8600\nRED_ALERT_API_KEY=sk-from-file\n",
        encoding="utf-8",
    )
    values = read_env_file(path)
    assert values["RED_ALERT_TARGET"] == "http://stand:8600"
    assert values["RED_ALERT_API_KEY"] == "sk-from-file"


def test_resolve_config_accepts_full_chat_url() -> None:
    config = resolve_config(
        target="http://localhost:8600/v1/chat/completions",
        api_key="sk-attacker",
        victim_api_key="sk-victim",
        scenario="memory-poisoning",
        attempts=1,
        environ={},
    )
    assert config.target == "http://localhost:8600"
