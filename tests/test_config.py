from pathlib import Path

from red_alert.config import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_OPENAI_BASE_URL,
    UsageError,
    env_flag,
    normalize_llm_base,
    normalize_target,
    read_env_file,
    resolve_config,
)

LLM_ENV = {
    "OPENAI_API_KEY": "sk-planner",
    "MODEL": "openai/gpt-5-mini",
}


def test_normalize_target_strips_chat_path() -> None:
    assert normalize_target("http://localhost:8600/v1/chat/completions") == "http://localhost:8600"


def test_normalize_target_keeps_base_url() -> None:
    assert normalize_target("http://localhost:8600/") == "http://localhost:8600"


def test_normalize_llm_base_strips_chat_path() -> None:
    assert (
        normalize_llm_base("https://openrouter.ai/api/v1/chat/completions")
        == "https://openrouter.ai/api/v1"
    )


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
        environ=LLM_ENV,
    )
    assert config.target == "http://localhost:8600"
    assert config.openai_base_url == DEFAULT_OPENAI_BASE_URL
    assert config.max_tokens == DEFAULT_MAX_TOKENS
    assert config.model == "openai/gpt-5-mini"
    assert config.debug is False


def test_resolve_config_reads_llm_overrides() -> None:
    config = resolve_config(
        target=None,
        api_key="sk-attacker",
        victim_api_key="sk-victim",
        scenario="memory-poisoning",
        attempts=1,
        environ={
            **LLM_ENV,
            "OPENAI_BASE_URL": "https://example.test/v1/chat/completions",
            "MAX_TOKENS": "512",
        },
    )
    assert config.openai_base_url == "https://example.test/v1"
    assert config.max_tokens == 512


def test_resolve_config_rejects_bad_max_tokens() -> None:
    try:
        resolve_config(
            target=None,
            api_key="sk-attacker",
            victim_api_key="sk-victim",
            scenario="memory-poisoning",
            attempts=1,
            environ={**LLM_ENV, "MAX_TOKENS": "nope"},
        )
    except UsageError as exc:
        assert "MAX_TOKENS" in str(exc)
    else:
        raise AssertionError("expected UsageError")


def test_env_flag() -> None:
    assert env_flag("1") is True
    assert env_flag("true") is True
    assert env_flag("YES") is True
    assert env_flag("on") is True
    assert env_flag("0") is False
    assert env_flag(None) is False


def test_resolve_config_debug_from_env() -> None:
    config = resolve_config(
        target=None,
        api_key="sk-attacker",
        victim_api_key="sk-victim",
        scenario="memory-poisoning",
        attempts=1,
        environ={**LLM_ENV, "RED_ALERT_DEBUG": "yes"},
    )
    assert config.debug is True
