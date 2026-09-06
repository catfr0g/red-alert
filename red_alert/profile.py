from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class OperationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str | None = None
    endpoint: str | None = None
    bearer_from: Literal["target", "eval"] | None = None
    custom_body: dict[str, Any] | None = None
    custom_headers: dict[str, Any] | None = None
    expected_body: dict[str, Any] | None = None

    def overlay(self, base: "OperationSpec") -> "OperationSpec":
        data = base.model_dump()
        own = self.model_dump()
        for name in ("method", "endpoint", "bearer_from"):
            if own[name] is not None:
                data[name] = own[name]
        for name in ("custom_body", "custom_headers", "expected_body"):
            data[name] = {**(data[name] or {}), **(own[name] or {})} or None
        return OperationSpec.model_validate(data)


class ConnectionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inherit: Literal["target", "defaults"] | None = None
    endpoint: str | None = None
    bearer_env: str | None = None
    model: str | None = None
    prompt: str | None = None
    custom_body: dict[str, Any] | None = None
    custom_headers: dict[str, Any] | None = None

    def overlay(self, base: "ConnectionSpec") -> "ConnectionSpec":
        """Собрать self поверх base: скаляры перекрывают, словари сливаются по ключам."""
        data = base.model_dump()
        own = self.model_dump()
        for name in ("endpoint", "bearer_env", "model", "prompt"):
            if own[name] is not None:
                data[name] = own[name]
        for name in ("custom_body", "custom_headers"):
            data[name] = {**(data[name] or {}), **(own[name] or {})} or None
        data["inherit"] = None
        return ConnectionSpec.model_validate(data)


class DefaultsSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: ConnectionSpec | None = None
    eval: ConnectionSpec | None = None
    persist: OperationSpec | None = None


class BindingRuntime(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: ConnectionSpec = Field(default_factory=ConnectionSpec)
    eval: ConnectionSpec = Field(default_factory=ConnectionSpec)
    persist: OperationSpec | None = None


class StandProfile(BaseModel):
    source: str | None = None
    context: str | None = None
    reset: OperationSpec | None = None
    defaults: DefaultsSpec | None = None
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

    def runtime(self, binding_name: str) -> BindingRuntime:
        raw = self.bindings.get(binding_name) or {}
        if raw.get("applicable") is False:
            return BindingRuntime()
        defaults = self.defaults or DefaultsSpec()
        try:
            target_spec = ConnectionSpec.model_validate(raw.get("target") or {})
            eval_spec = ConnectionSpec.model_validate(raw.get("eval") or {})
            persist_raw = raw.get("persist")
            persist_spec = (
                OperationSpec.model_validate(persist_raw)
                if isinstance(persist_raw, dict)
                else None
            )
            target = target_spec.overlay(defaults.target or ConnectionSpec())
            if eval_spec.inherit == "target":
                base_eval = target
            else:
                base_eval = defaults.eval or ConnectionSpec()
            persist = (
                persist_spec.overlay(defaults.persist or OperationSpec())
                if persist_spec is not None
                else None
            )
            return BindingRuntime(
                target=target,
                eval=eval_spec.overlay(base_eval),
                persist=persist,
            )
        except Exception as exc:
            raise UsageError(f"{binding_name}: невалидная runtime-конфигурация: {exc}") from exc


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


def dump_profile(profile: StandProfile) -> str:
    payload = profile.model_dump()
    connection_defaults = {
        "inherit": None,
        "endpoint": None,
        "bearer_env": None,
        "model": None,
        "prompt": None,
        "custom_body": None,
        "custom_headers": None,
    }
    payload["bindings"] = {
        name: {
            **binding,
            "target": {**connection_defaults, **(binding.get("target") or {})},
            "eval": {**connection_defaults, **(binding.get("eval") or {})},
            "persist": binding.get("persist"),
        }
        for name, binding in profile.bindings.items()
    }
    return yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)


PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def render_runtime_value(
    value: Any,
    *,
    builtins: Mapping[str, str],
    environ: Mapping[str, str],
) -> Any:
    if isinstance(value, str):
        missing: set[str] = set()

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            resolved = builtins.get(name)
            if resolved is None:
                resolved = environ.get(name)
            if resolved is None:
                missing.add(name)
                return match.group(0)
            return resolved

        rendered = PLACEHOLDER_RE.sub(replace, value)
        if missing:
            raise UsageError("Не заданы runtime-переменные: " + ", ".join(sorted(missing)))
        return rendered
    if isinstance(value, list):
        return [render_runtime_value(item, builtins=builtins, environ=environ) for item in value]
    if isinstance(value, dict):
        return {
            key: render_runtime_value(item, builtins=builtins, environ=environ)
            for key, item in value.items()
        }
    return value
