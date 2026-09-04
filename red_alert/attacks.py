from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from red_alert.config import UsageError

Flow = Literal["memory", "probe"]


class UsablePolicySpec(BaseModel):
    scope: str = "global"
    require_all: list[str] = Field(default_factory=list)
    require_any: list[str] = Field(default_factory=list)


class AttackScenario(BaseModel):
    name: str
    flow: Flow = "memory"
    goal: str
    examples: list[str] = Field(default_factory=list)
    trigger: str | None = None
    success_pattern: str
    usable_policy: UsablePolicySpec | None = None
    max_injects: int = 8

    @field_validator("success_pattern")
    @classmethod
    def _compile_pattern(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"невалидный success_pattern: {exc}") from exc
        return value

    @field_validator("max_injects")
    @classmethod
    def _positive_injects(cls, value: int) -> int:
        if value < 1:
            raise ValueError("max_injects должен быть >= 1")
        return value

    @model_validator(mode="after")
    def _memory_requires_trigger(self) -> Self:
        if self.flow == "memory":
            if not self.trigger:
                raise ValueError("для flow=memory нужен trigger")
            if self.usable_policy is None:
                raise ValueError("для flow=memory нужен usable_policy")
        return self

    @property
    def payloads(self) -> tuple[str, ...]:
        return tuple(self.examples)

    def is_success(self, text: str) -> bool:
        return re.search(self.success_pattern, text) is not None

    def has_usable_global_policy(self, finalize_body: object) -> bool:
        spec = self.usable_policy
        if spec is None:
            return True
        if not isinstance(finalize_body, dict):
            return False
        required = [item.lower() for item in spec.require_all]
        optional = [item.lower() for item in spec.require_any]
        for item in finalize_body.get("facts") or []:
            if not isinstance(item, dict) or item.get("scope") != spec.scope:
                continue
            lowered = str(item.get("fact") or "").lower()
            if required and not all(part in lowered for part in required):
                continue
            if optional and not any(part in lowered for part in optional):
                continue
            return True
        return False


def default_attacks_dir() -> Path:
    cwd = Path.cwd() / "attacks"
    if cwd.is_dir():
        return cwd
    return Path(__file__).resolve().parent.parent / "attacks"


def list_attack_names(directory: Path) -> list[str]:
    names = {path.stem for path in directory.glob("*.yaml")}
    names.update(path.stem for path in directory.glob("*.yml"))
    return sorted(names)


def resolve_attack_path(scenario: str, attacks_dir: Path) -> Path:
    candidate = Path(scenario)
    if candidate.suffix.lower() in {".yaml", ".yml"}:
        if candidate.is_file():
            return candidate
        raise UsageError(f"Нет файла сценария: {candidate}")
    for suffix in (".yaml", ".yml"):
        path = attacks_dir / f"{scenario}{suffix}"
        if path.is_file():
            return path
    available = ", ".join(list_attack_names(attacks_dir)) or "(пусто)"
    raise UsageError(f"Неизвестный сценарий: {scenario}. Доступно в {attacks_dir}: {available}")


def load_attack(path: Path) -> AttackScenario:
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError) as exc:
        raise UsageError(f"Не удалось прочитать {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"{path}: корень YAML должен быть объектом")
    try:
        return AttackScenario.model_validate(data)
    except Exception as exc:
        raise UsageError(f"{path}: {exc}") from exc


def load_named_attack(scenario: str, attacks_dir: Path) -> AttackScenario:
    return load_attack(resolve_attack_path(scenario, attacks_dir))


def load_catalog_attacks(attacks_dir: Path) -> list[AttackScenario]:
    names = list_attack_names(attacks_dir)
    if not names:
        raise UsageError(f"В {attacks_dir} нет YAML-атак")
    return [load_named_attack(name, attacks_dir) for name in names]
