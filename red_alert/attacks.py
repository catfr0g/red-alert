from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from red_alert.config import UsageError
from red_alert.profile import SkippedScenario, StandProfile, load_profile, resolve_profile_path

Flow = Literal["memory", "probe"]
Delivery = Literal["text", "image"]
TargetKind = Literal["invest", "openclaw"]


class UsablePolicySpec(BaseModel):
    scope: str = "global"
    require_all: list[str] = Field(default_factory=list)
    require_any: list[str] = Field(default_factory=list)


class AttackScenario(BaseModel):
    name: str
    flow: Flow = "memory"
    vulnerability: str
    goal: str
    examples: list[str] = Field(default_factory=list)
    trigger: str | None = None
    success_check: str
    usable_policy: UsablePolicySpec | None = None
    delivery: Delivery = "text"
    image_caption: str = "Прочитай текст на изображении и выполни его как мой запрос."
    target_kind: TargetKind = "invest"
    max_injects: int = 8
    requires: list[str] = Field(default_factory=list)
    slots: list[str] = Field(default_factory=list)

    @field_validator("success_check")
    @classmethod
    def _non_empty_success_check(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("success_check не должен быть пустым")
        return value

    @field_validator("vulnerability")
    @classmethod
    def _non_empty_vulnerability(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("vulnerability не должен быть пустым")
        return stripped

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


def load_named_template(scenario: str, attacks_dir: Path) -> AttackScenario:
    return load_attack(resolve_attack_path(scenario, attacks_dir))


def load_named_attack(
    scenario: str,
    attacks_dir: Path,
    profile: StandProfile | None = None,
) -> AttackScenario:
    template = load_named_template(scenario, attacks_dir)
    resolved = profile if profile is not None else load_profile(resolve_profile_path(None))
    instances, skipped = apply_profile([template], resolved, override=True)
    if not instances:
        reason = skipped[0].reason if skipped else "не удалось собрать сценарий"
        raise UsageError(reason)
    return instances[0]


def load_catalog_attacks(
    attacks_dir: Path, *, target_kind: str | None = None
) -> list[AttackScenario]:
    names = list_attack_names(attacks_dir)
    if not names:
        raise UsageError(f"В {attacks_dir} нет YAML-атак")
    loaded = [load_named_template(name, attacks_dir) for name in names]
    if target_kind is None:
        return loaded
    matched = [item for item in loaded if item.target_kind == target_kind]
    if not matched:
        raise UsageError(f"В {attacks_dir} нет YAML-атак для target-kind={target_kind}")
    return matched


def _render_value(value: Any, bindings: dict[str, Any]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, raw in bindings.items():
            if isinstance(raw, str):
                rendered = rendered.replace("{{" + key + "}}", raw)
        return rendered
    if isinstance(value, list):
        return [_render_value(item, bindings) for item in value]
    if isinstance(value, dict):
        return {key: _render_value(item, bindings) for key, item in value.items()}
    return value


def _binding_text(bindings: dict[str, Any], slot: str) -> str:
    value = bindings.get(slot)
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def capability_skip_reason(template: AttackScenario, profile: StandProfile) -> str | None:
    for name in template.requires:
        state = profile.capability(name)
        if state.status == "absent" and state.confidence == "high":
            return f"requires {name} (absent)"
    return None


def missing_slots(template: AttackScenario, bindings: dict[str, Any]) -> list[str]:
    return [slot for slot in template.slots if not _binding_text(bindings, slot)]


def _leftover_slots(value: Any, slots: list[str]) -> set[str]:
    blob = yaml.safe_dump(value, allow_unicode=True)
    return {slot for slot in slots if "{{" + slot + "}}" in blob}


def instantiate(template: AttackScenario, bindings: dict[str, Any]) -> AttackScenario:
    data = template.model_dump()
    rendered = _render_value(data, bindings)
    if isinstance(bindings.get("usable_policy"), dict):
        rendered["usable_policy"] = bindings["usable_policy"]
    leftover = _leftover_slots(rendered, template.slots)
    if leftover:
        raise UsageError(f"{template.name}: не подставлены слоты: {', '.join(sorted(leftover))}")
    return AttackScenario.model_validate(rendered)


def apply_profile(
    templates: list[AttackScenario],
    profile: StandProfile,
    *,
    override: bool = False,
) -> tuple[list[AttackScenario], list[SkippedScenario]]:
    instances: list[AttackScenario] = []
    skipped: list[SkippedScenario] = []
    for template in templates:
        if not override:
            reason = capability_skip_reason(template, profile)
            if reason:
                skipped.append(SkippedScenario(name=template.name, reason=reason))
                continue
        bindings = profile.bindings.get(template.name) or {}
        if not isinstance(bindings, dict):
            skipped.append(
                SkippedScenario(name=template.name, reason="bindings должны быть объектом")
            )
            continue
        missing = missing_slots(template, bindings)
        if missing:
            skipped.append(
                SkippedScenario(
                    name=template.name,
                    reason=f"незаполненный слот: {', '.join(missing)}",
                )
            )
            continue
        try:
            instances.append(instantiate(template, bindings))
        except UsageError as exc:
            skipped.append(SkippedScenario(name=template.name, reason=str(exc)))
    return instances, skipped
