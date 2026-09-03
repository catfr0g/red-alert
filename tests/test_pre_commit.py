from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / ".pre-commit-config.yaml"


def test_pre_commit_config_uses_official_ruff_and_ty_hooks() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    assert "astral-sh/ruff-pre-commit" in text
    assert "id: ruff-check" in text
    assert "astral-sh/ty-pre-commit" in text
    assert "id: ty" in text


def test_pre_commit_config_runs_pytest() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    assert "id: pytest" in text
    assert "uv run pytest" in text
