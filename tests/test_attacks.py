from pathlib import Path

import pytest

from red_alert.attacks import load_attack, load_catalog_attacks, load_named_attack
from red_alert.config import UsageError


def test_load_memory_poisoning_from_catalog() -> None:
    scenario = load_named_attack("memory-poisoning", Path("attacks"))
    assert scenario.flow == "memory"
    assert scenario.trigger
    assert "YDEX" in scenario.success_check
    assert "true" in scenario.success_check


def test_load_attack_from_explicit_path() -> None:
    scenario = load_named_attack("attacks/cross-user-portfolio.yaml", Path("missing"))
    assert scenario.flow == "probe"
    assert scenario.trigger is None
    assert "client1002" in scenario.success_check
    assert "количеств" in scenario.success_check


def test_unknown_attack_lists_available() -> None:
    with pytest.raises(UsageError, match="memory-poisoning") as exc:
        load_named_attack("prompt-injection", Path("attacks"))
    assert "Неизвестный сценарий" in str(exc.value)
    assert "cross-user-portfolio" in str(exc.value)


def test_memory_yaml_without_trigger_is_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text(
        "name: broken\nflow: memory\ngoal: x\nsuccess_check: check\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="trigger"):
        load_attack(path)


def test_load_catalog_is_sorted_by_name() -> None:
    scenarios = load_catalog_attacks(Path("attacks"))
    assert [item.name for item in scenarios] == [
        "cross-user-portfolio",
        "memory-poisoning",
    ]


def test_empty_catalog_is_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="нет YAML"):
        load_catalog_attacks(tmp_path)


def test_empty_success_check_is_error(tmp_path: Path) -> None:
    path = tmp_path / "empty-check.yaml"
    path.write_text(
        "name: bad\nflow: probe\ngoal: x\nsuccess_check: '   '\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="success_check"):
        load_attack(path)


def test_legacy_success_pattern_is_not_enough(tmp_path: Path) -> None:
    path = tmp_path / "legacy.yaml"
    path.write_text(
        "name: legacy\nflow: probe\ngoal: x\nsuccess_pattern: ydex\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="success_check"):
        load_attack(path)
