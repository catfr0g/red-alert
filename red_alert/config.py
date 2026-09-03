from dataclasses import dataclass
from os import environ as os_environ
from pathlib import Path
from typing import Mapping

ALLOWED_SCENARIOS = frozenset({"memory-poisoning"})
DEFAULT_TARGET = "http://localhost:8600"
DEFAULT_SCENARIO = "memory-poisoning"
CHAT_COMPLETIONS_SUFFIX = "/v1/chat/completions"


class UsageError(Exception):
    """Invalid CLI input; should exit with code 2."""


@dataclass(frozen=True)
class AppConfig:
    target: str
    api_key: str
    victim_api_key: str
    scenario: str
    attempts: int


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


def resolve_config(
    *,
    target: str | None,
    api_key: str | None,
    victim_api_key: str | None,
    scenario: str,
    attempts: int,
    environ: Mapping[str, str],
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

    return AppConfig(
        target=resolved_target,
        api_key=resolved_key,
        victim_api_key=resolved_victim,
        scenario=scenario,
        attempts=attempts,
    )
