from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from red_alert.config import UsageError

CapabilityName = Literal["persistent_memory", "multi_user", "vision"]
CapabilityStatus = Literal["present", "absent", "unknown"]
Confidence = Literal["high", "low"]

KNOWN_CAPABILITIES: tuple[str, ...] = ("persistent_memory", "multi_user", "vision")


class CapabilityState(BaseModel):
    status: CapabilityStatus = "unknown"
    confidence: Confidence = "low"


class SkippedScenario(BaseModel):
    name: str
    reason: str


class StandProfile(BaseModel):
    source: str | None = None
    capabilities: dict[str, CapabilityState] = Field(default_factory=dict)
    bindings: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def _known_capabilities(cls, value: dict[str, CapabilityState]) -> dict[str, CapabilityState]:
        unknown = sorted(set(value) - set(KNOWN_CAPABILITIES))
        if unknown:
            raise ValueError(f"неизвестные capability: {', '.join(unknown)}")
        return value

    def capability(self, name: str) -> CapabilityState:
        return self.capabilities.get(name, CapabilityState())


def default_profiles_dir() -> Path:
    cwd = Path.cwd() / "profiles"
    if cwd.is_dir():
        return cwd
    return Path(__file__).resolve().parent.parent / "profiles"


def default_profile_path() -> Path:
    return default_profiles_dir() / "invest-stand.yaml"


def load_profile(path: Path) -> StandProfile:
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError) as exc:
        raise UsageError(f"Не удалось прочитать профиль {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"{path}: корень YAML должен быть объектом")
    try:
        return StandProfile.model_validate(data)
    except Exception as exc:
        raise UsageError(f"{path}: {exc}") from exc


def resolve_profile_path(raw: str | None) -> Path:
    if raw:
        path = Path(raw)
        if not path.is_file():
            raise UsageError(f"Нет файла профиля: {path}")
        return path
    path = default_profile_path()
    if not path.is_file():
        raise UsageError(f"Нет упакованного профиля: {path}")
    return path


def dump_profile(profile: StandProfile) -> str:
    payload = profile.model_dump(exclude_none=True)
    return yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)
