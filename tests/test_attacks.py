from pathlib import Path

import pytest

from red_alert.attacks import (
    AttackScenario,
    apply_profile,
    load_catalog_attacks,
    load_named_attack,
    load_named_template,
)
from red_alert.config import UsageError
from red_alert.profile import StandProfile


def _profile(name: str, values: dict[str, str]) -> StandProfile:
    return StandProfile.model_validate(
        {
            "bindings": {
                name: {
                    **values,
                    "target": {"endpoint": "https://agent.test/v1/chat/completions"},
                    "eval": {"inherit": "target"},
                    "persist": None,
                }
            }
        }
    )


def test_catalog_contains_generic_templates_sorted_by_name() -> None:
    attacks = load_catalog_attacks(Path("attacks"))
    names = [item.name for item in attacks]
    assert names == sorted(names)
    assert "memory-poisoning" in names
    assert "openclaw-goal-hijack" in names
    assert all(not hasattr(item, "target_kind") for item in attacks)


def test_named_attack_requires_and_applies_profile() -> None:
    profile = _profile(
        "memory-poisoning",
        {"policy": "global policy", "trigger": "check", "proof": "policy applied"},
    )
    scenario = load_named_attack("memory-poisoning", Path("attacks"), profile)
    assert scenario.flow == "memory"
    assert "global policy" in scenario.goal
    assert scenario.trigger == "check"


def test_explicit_template_path_loads_without_target_specific_config() -> None:
    template = load_named_template("attacks/cross-user-portfolio.yaml", Path("missing"))
    assert template.name == "cross-user-portfolio"
    assert template.flow == "probe"


def test_unknown_attack_lists_available() -> None:
    with pytest.raises(UsageError, match="memory-poisoning"):
        load_named_template("missing-attack", Path("attacks"))


def test_missing_slot_and_endpoint_are_skipped() -> None:
    template = load_named_template("cross-user-portfolio", Path("attacks"))
    profile = _profile(
        "cross-user-portfolio",
        {"target_client": "", "target_ticker": "YDEX", "proof": "leak"},
    )
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert "слот" in skipped[0].reason

    profile.bindings["cross-user-portfolio"]["target"]["endpoint"] = None
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert "target.endpoint" in skipped[0].reason


def test_attack_scenario_validates_memory_trigger() -> None:
    with pytest.raises(ValueError, match="trigger"):
        AttackScenario(
            name="memory",
            flow="memory",
            vulnerability="memory",
            goal="goal",
            success_check="proof",
        )
