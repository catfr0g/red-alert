from dataclasses import dataclass
from os import environ as os_environ
from pathlib import Path
from typing import Mapping

DEFAULT_OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MAX_TOKENS = 2048
DEFAULT_ISOLATION = "on"
DEFAULT_LANGFUSE_BASE_URL = "http://localhost:3000"
ALLOWED_ISOLATION = ("on", "off")
ISOLATION_OFF_WARNING = (
    "Изоляция выключена: попытки могут наследовать память предыдущих прогонов, ASR не независим."
)
CHAT_COMPLETIONS_TAIL = "/chat/completions"


class UsageError(Exception):
    """Invalid CLI input; should exit with code 2."""


@dataclass(frozen=True)
class AppConfig:
    scenario: str | None
    attempts: int
    openai_api_key: str
    attack_openai_base_url: str
    judge_openai_base_url: str
    attack_model: str
    judge_model: str
    max_tokens: int
    debug: bool
    attacks_dir: Path
    profile: str
    isolation: str = DEFAULT_ISOLATION
    langfuse_enabled: bool = False
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_base_url: str = DEFAULT_LANGFUSE_BASE_URL


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


def env_flag(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_isolation(raw: str | None) -> str:
    value = (raw or DEFAULT_ISOLATION).strip().lower()
    if value in ALLOWED_ISOLATION:
        return value
    raise UsageError("--isolate / RED_ALERT_ISOLATE: on или off")


def normalize_llm_base(url: str) -> str:
    resolved = url.strip().rstrip("/")
    if resolved.endswith(CHAT_COMPLETIONS_TAIL):
        resolved = resolved[: -len(CHAT_COMPLETIONS_TAIL)].rstrip("/")
    return resolved


def resolve_config(
    *,
    scenario: str | None,
    attempts: int,
    environ: Mapping[str, str],
    debug: bool = False,
    attacks_dir: str | None = None,
    profile: str | None = None,
    isolation: str | None = None,
) -> AppConfig:
    if attempts < 1:
        raise UsageError("--attempts должен быть >= 1")
    resolved_profile = profile or environ.get("RED_ALERT_PROFILE")
    if not resolved_profile:
        raise UsageError("Нужен --profile или переменная RED_ALERT_PROFILE")

    openai_api_key = environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        raise UsageError("Нужна переменная OPENAI_API_KEY")
    attack_model = environ.get("MODEL_ATTACK")
    if not attack_model:
        raise UsageError("Нужна переменная MODEL_ATTACK")
    judge_model = environ.get("MODEL_JUDGE")
    if not judge_model:
        raise UsageError("Нужна переменная MODEL_JUDGE")

    raw_tokens = environ.get("MAX_TOKENS", str(DEFAULT_MAX_TOKENS))
    try:
        max_tokens = int(raw_tokens)
    except ValueError:
        raise UsageError("MAX_TOKENS должен быть целым числом >= 1") from None
    if max_tokens < 1:
        raise UsageError("MAX_TOKENS должен быть целым числом >= 1")

    attack_openai_base_url = normalize_llm_base(
        environ.get("OPENAI_BASE_URL_ATTACK") or DEFAULT_OPENAI_BASE_URL
    )
    judge_openai_base_url = normalize_llm_base(
        environ.get("OPENAI_BASE_URL_JUDGE") or DEFAULT_OPENAI_BASE_URL
    )

    raw_dir = attacks_dir or environ.get("RED_ALERT_ATTACKS_DIR")
    if raw_dir:
        resolved_attacks_dir = Path(raw_dir)
    else:
        cwd_attacks = Path.cwd() / "attacks"
        packaged = Path(__file__).resolve().parent.parent / "attacks"
        resolved_attacks_dir = cwd_attacks if cwd_attacks.is_dir() else packaged

    langfuse_enabled = env_flag(environ.get("RED_ALERT_LANGFUSE"))
    langfuse_public_key = (environ.get("LANGFUSE_PUBLIC_KEY") or "").strip()
    langfuse_secret_key = (environ.get("LANGFUSE_SECRET_KEY") or "").strip()
    langfuse_base_url = (
        (environ.get("LANGFUSE_BASE_URL") or DEFAULT_LANGFUSE_BASE_URL).strip().rstrip("/")
    )
    if langfuse_enabled and not langfuse_public_key:
        raise UsageError("Нужна переменная LANGFUSE_PUBLIC_KEY")
    if langfuse_enabled and not langfuse_secret_key:
        raise UsageError("Нужна переменная LANGFUSE_SECRET_KEY")

    return AppConfig(
        scenario=scenario or None,
        attempts=attempts,
        openai_api_key=openai_api_key,
        attack_openai_base_url=attack_openai_base_url,
        judge_openai_base_url=judge_openai_base_url,
        attack_model=attack_model,
        judge_model=judge_model,
        max_tokens=max_tokens,
        debug=debug or env_flag(environ.get("RED_ALERT_DEBUG")),
        attacks_dir=resolved_attacks_dir,
        profile=resolved_profile,
        isolation=resolve_isolation(
            isolation if isolation is not None else environ.get("RED_ALERT_ISOLATE")
        ),
        langfuse_enabled=langfuse_enabled,
        langfuse_public_key=langfuse_public_key,
        langfuse_secret_key=langfuse_secret_key,
        langfuse_base_url=langfuse_base_url,
    )
