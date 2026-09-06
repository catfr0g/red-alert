from pathlib import Path

import pytest

from red_alert.attacks import apply_profile, load_named_template
from red_alert.config import UsageError
from red_alert.profile import (
    CapabilityState,
    StandProfile,
    load_profile,
    resolve_profile_path,
)


def _profile(**overrides: object) -> StandProfile:
    data = load_profile(resolve_profile_path(None)).model_dump()
    data.update(overrides)
    return StandProfile.model_validate(data)


def test_default_profile_is_invest_stand() -> None:
    profile = load_profile(resolve_profile_path(None))
    assert profile.capability("persistent_memory").status == "present"
    assert profile.capability("vision").status == "present"
    assert "memory-poisoning" in profile.bindings


def test_missing_capability_is_unknown() -> None:
    profile = StandProfile(capabilities={})
    state = profile.capability("vision")
    assert state.status == "unknown"
    assert state.confidence == "low"


def test_unknown_capability_key_is_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "capabilities:\n  tools:\n    status: present\n    confidence: high\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="capability"):
        load_profile(path)


def test_invalid_status_is_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "capabilities:\n  vision:\n    status: maybe\n    confidence: high\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError):
        load_profile(path)


def test_missing_profile_file(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="Нет файла профиля"):
        resolve_profile_path(str(tmp_path / "nope.yaml"))


def test_vision_absent_skips_image_attack() -> None:
    profile = _profile(
        capabilities={
            "persistent_memory": {"status": "present", "confidence": "high"},
            "multi_user": {"status": "present", "confidence": "high"},
            "vision": {"status": "absent", "confidence": "high"},
        }
    )
    template = load_named_template("memory-poisoning-image-injection", Path("attacks"))
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert skipped[0].name == "memory-poisoning-image-injection"
    assert "vision" in skipped[0].reason


def test_unknown_memory_does_not_skip() -> None:
    invest = load_profile(resolve_profile_path(None))
    profile = StandProfile(
        capabilities={"persistent_memory": CapabilityState(status="unknown", confidence="low")},
        bindings=invest.bindings,
    )
    template = load_named_template("memory-poisoning", Path("attacks"))
    instances, skipped = apply_profile([template], profile)
    assert [item.name for item in instances] == ["memory-poisoning"]
    assert skipped == []


def test_empty_slot_skips() -> None:
    profile = StandProfile(
        capabilities={"persistent_memory": CapabilityState(status="present", confidence="high")},
        bindings={"memory-poisoning": {"trigger": "hi", "proof": "ok"}},
    )
    template = load_named_template("memory-poisoning", Path("attacks"))
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert "слот" in skipped[0].reason


def test_override_runs_despite_absent_vision() -> None:
    invest = load_profile(resolve_profile_path(None))
    profile = StandProfile(
        capabilities={"vision": CapabilityState(status="absent", confidence="high")},
        bindings=invest.bindings,
    )
    template = load_named_template("memory-poisoning-image-injection", Path("attacks"))
    instances, skipped = apply_profile([template], profile, override=True)
    assert [item.name for item in instances] == ["memory-poisoning-image-injection"]
    assert skipped == []
