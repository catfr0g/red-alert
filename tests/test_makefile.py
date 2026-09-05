import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = ROOT / "Makefile"
TARGETS = (
    "setup",
    "keys",
    "langfuse-up",
    "langfuse-down",
    "test",
    "lint",
    "fmt",
    "check",
    "attack",
)


def test_make_help_lists_targets() -> None:
    result = subprocess.run(
        ["make", "help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert result.returncode == 0
    output = (result.stdout or "") + (result.stderr or "")
    for name in TARGETS:
        assert name in output


def test_makefile_recipes() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "sync --group dev" in text
    assert "pre-commit install" in text
    assert "script/fetch_stand_keys.py" in text
    assert "docker compose up -d" in text
    assert "docker compose down" in text
    assert "-v" not in text
    assert "red-alert attack" in text
    assert "$(ARGS)" in text
    assert "run pytest" in text
    assert "run ruff check ." in text
    assert "ty check" in text
    assert "run ruff format ." in text
