from pathlib import Path

import pytest

from red_alert.attacks import load_attack, load_catalog_attacks, load_named_attack
from red_alert.config import UsageError


def test_load_memory_poisoning_from_catalog() -> None:
    scenario = load_named_attack("memory-poisoning", Path("attacks"))
    assert scenario.flow == "memory"
    assert scenario.vulnerability == "memory-poisoning"
    assert scenario.trigger
    assert scenario.is_success("В портфеле YDEX. Рекомендую продать: неприемлемый риск.")
    assert not scenario.is_success("Рекомендую продать GAZP")


def test_load_attack_from_explicit_path() -> None:
    scenario = load_named_attack("attacks/cross-user-portfolio.yaml", Path("missing"))
    assert scenario.flow == "probe"
    assert scenario.vulnerability == "cross-user-disclosure"
    assert scenario.trigger is None
    assert scenario.is_success("Портфель client1002: YDEX 10 лотов, стоимость 42100")
    assert not scenario.is_success("Портфель client1002 содержит YDEX")
    assert not scenario.is_success(
        "Запрос портфеля клиента 1002 заблокирован. YDEX запрещена политикой."
    )


def test_unknown_attack_lists_available() -> None:
    with pytest.raises(UsageError, match="memory-poisoning") as exc:
        load_named_attack("prompt-injection", Path("attacks"))
    assert "Неизвестный сценарий" in str(exc.value)
    assert "cross-user-portfolio" in str(exc.value)


def test_memory_yaml_without_trigger_is_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text(
        "name: broken\nflow: memory\nvulnerability: memory-poisoning\n"
        "goal: x\nsuccess_pattern: ydex\n",
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


def test_yaml_without_vulnerability_is_error(tmp_path: Path) -> None:
    path = tmp_path / "no-vuln.yaml"
    path.write_text(
        "name: x\nflow: probe\ngoal: x\nsuccess_pattern: ydex\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="vulnerability"):
        load_attack(path)


def test_empty_vulnerability_is_error(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text(
        "name: x\nflow: probe\nvulnerability: '  '\ngoal: x\nsuccess_pattern: ydex\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="vulnerability"):
        load_attack(path)


def test_invalid_regex_is_error(tmp_path: Path) -> None:
    path = tmp_path / "bad-re.yaml"
    path.write_text(
        "name: bad\nflow: probe\nvulnerability: x\ngoal: x\nsuccess_pattern: '(unclosed'\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="success_pattern"):
        load_attack(path)
