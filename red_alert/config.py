from dataclasses import dataclass
from os import environ as os_environ
from pathlib import Path
from typing import Mapping

ALLOWED_SCENARIOS = frozenset({"memory-poisoning"})
DEFAULT_TARGET = "http://localhost:8600"
DEFAULT_SCENARIO = "memory-poisoning"
DEFAULT_OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MAX_TOKENS = 2048
CHAT_COMPLETIONS_SUFFIX = "/v1/chat/completions"
CHAT_COMPLETIONS_TAIL = "/chat/completions"


class UsageError(Exception):
    """Invalid CLI input; should exit with code 2."""


@dataclass(frozen=True)
class AppConfig:
    target: str
    api_key: str
    victim_api_key: str
    scenario: str
    attempts: int
    openai_api_key: str
    openai_base_url: str
    model: str
    max_tokens: int
    debug: bool


def read_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'").strip('"')
    return values


def merged_environ(
    environ: Mapping[str, str] | None = None,
    *,
    dotenv_path: Path | None = None,
) -> dict[str, str]:
    file_vars = read_env_file(dotenv_path if dotenv_path is not None else Path.cwd() / ".env")
    overlay = dict(environ) if environ is not None else dict(os_environ)
    return {**file_vars, **overlay}


def normalize_target(target: str) -> str:
    resolved = target.strip().rstrip("/")
    if resolved.endswith(CHAT_COMPLETIONS_SUFFIX):
        resolved = resolved[: -len(CHAT_COMPLETIONS_SUFFIX)].rstrip("/")
    return resolved


def env_flag(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_llm_base(url: str) -> str:
    resolved = url.strip().rstrip("/")
    if resolved.endswith(CHAT_COMPLETIONS_TAIL):
        resolved = resolved[: -len(CHAT_COMPLETIONS_TAIL)].rstrip("/")
    return resolved


def resolve_config(
    *,
    target: str | None,
    api_key: str | None,
    victim_api_key: str | None,
    scenario: str,
    attempts: int,
    environ: Mapping[str, str],
    debug: bool = False,
) -> AppConfig:
    resolved_key = api_key or environ.get("RED_ALERT_API_KEY")
    if not resolved_key:
        raise UsageError("Нужен --api-key или переменная RED_ALERT_API_KEY")

    resolved_victim = victim_api_key or environ.get("RED_ALERT_VICTIM_API_KEY")
    if not resolved_victim:
        raise UsageError("Нужен --victim-api-key или переменная RED_ALERT_VICTIM_API_KEY")
    if resolved_victim == resolved_key:
        raise UsageError(
            "--api-key и --victim-api-key должны принадлежать разным пользователям стенда"
        )

    resolved_target = target or environ.get("RED_ALERT_TARGET") or DEFAULT_TARGET
    resolved_target = normalize_target(resolved_target)

    if scenario not in ALLOWED_SCENARIOS:
        raise UsageError(
            f"Неизвестный сценарий: {scenario}. Допустимо: {', '.join(sorted(ALLOWED_SCENARIOS))}"
        )
    if attempts < 1:
        raise UsageError("--attempts должен быть >= 1")

    openai_api_key = environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        raise UsageError("Нужна переменная OPENAI_API_KEY")
    model = environ.get("MODEL")
    if not model:
        raise UsageError("Нужна переменная MODEL")

    raw_tokens = environ.get("MAX_TOKENS", str(DEFAULT_MAX_TOKENS))
    try:
        max_tokens = int(raw_tokens)
    except ValueError:
        raise UsageError("MAX_TOKENS должен быть целым числом >= 1") from None
    if max_tokens < 1:
        raise UsageError("MAX_TOKENS должен быть целым числом >= 1")

    openai_base_url = normalize_llm_base(environ.get("OPENAI_BASE_URL") or DEFAULT_OPENAI_BASE_URL)

    return AppConfig(
        target=resolved_target,
        api_key=resolved_key,
        victim_api_key=resolved_victim,
        scenario=scenario,
        attempts=attempts,
        openai_api_key=openai_api_key,
        openai_base_url=openai_base_url,
        model=model,
        max_tokens=max_tokens,
        debug=debug or env_flag(environ.get("RED_ALERT_DEBUG")),
    )
