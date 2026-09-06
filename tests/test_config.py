from typing import Any

from red_alert.config import (
    DEFAULT_MAX_TOKENS,
    UsageError,
    normalize_llm_base,
    resolve_config,
    resolve_isolation,
)

LLM_ENV = {
    "OPENAI_API_KEY": "sk-planner",
    "MODEL_ATTACK": "attack-model",
    "MODEL_JUDGE": "judge-model",
}


def _resolve(**overrides: object):
    values: dict[str, Any] = {
        "scenario": None,
        "attempts": 1,
        "environ": LLM_ENV,
        "profile": "profile.yaml",
    }
    values.update(overrides)
    return resolve_config(**values)


def test_resolve_config_requires_profile() -> None:
    try:
        _resolve(profile=None)
    except UsageError as exc:
        assert "--profile" in str(exc)
    else:
        raise AssertionError("profile must be required")


def test_resolve_config_uses_profile_env() -> None:
    config = _resolve(profile=None, environ={**LLM_ENV, "RED_ALERT_PROFILE": "target.yaml"})
    assert config.profile == "target.yaml"


def test_resolve_config_requires_planner_settings() -> None:
    for missing in ("OPENAI_API_KEY", "MODEL_ATTACK", "MODEL_JUDGE"):
        environ = {**LLM_ENV}
        environ.pop(missing)
        try:
            _resolve(environ=environ)
        except UsageError as exc:
            assert missing in str(exc)
        else:
            raise AssertionError(f"{missing} must be required")


def test_resolve_config_normalizes_llm_urls() -> None:
    config = _resolve(
        environ={
            **LLM_ENV,
            "OPENAI_BASE_URL_ATTACK": "https://attack.test/v1/chat/completions",
            "OPENAI_BASE_URL_JUDGE": "https://judge.test/api/v1/chat/completions",
            "MAX_TOKENS": "512",
        }
    )
    assert config.attack_openai_base_url == "https://attack.test/v1"
    assert config.judge_openai_base_url == "https://judge.test/api/v1"
    assert config.max_tokens == 512


def test_resolve_config_defaults() -> None:
    config = _resolve()
    assert config.max_tokens == DEFAULT_MAX_TOKENS
    assert config.isolation == "on"
    assert config.scenario is None


def test_bad_attempts_and_tokens_are_rejected() -> None:
    for overrides in (
        {"attempts": 0},
        {"environ": {**LLM_ENV, "MAX_TOKENS": "bad"}},
        {"environ": {**LLM_ENV, "MAX_TOKENS": "0"}},
    ):
        try:
            _resolve(**overrides)
        except UsageError:
            pass
        else:
            raise AssertionError("invalid configuration must fail")


def test_isolation_and_llm_url_validation() -> None:
    assert resolve_isolation(None) == "on"
    assert resolve_isolation("off") == "off"
    assert normalize_llm_base("https://example.test/v1/chat/completions") == (
        "https://example.test/v1"
    )
    try:
        resolve_isolation("maybe")
    except UsageError:
        pass
    else:
        raise AssertionError("invalid isolation must fail")
