from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "install.sh"
INSTALL_PS1 = ROOT / "install.ps1"
REQUIREMENTS = ROOT / "requirements.txt"


def test_install_scripts_exist() -> None:
    assert INSTALL_SH.is_file()
    assert INSTALL_PS1.is_file()
    assert REQUIREMENTS.is_file()


def test_install_sh_recipe() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "dirname" in text
    assert "pyproject.toml" in text
    assert "requirements.txt" in text
    assert "-m venv" in text
    assert "pip install -r requirements.txt" in text
    assert ".local/bin" in text
    assert "PATH" in text
    assert ".env.example" in text
    assert "[[ ! -f .env ]]" in text
    assert "uv sync" not in text
    assert "--group dev" not in text
    assert "pre-commit install" not in text
    assert "astral.sh/uv" not in text
    assert "python-build-standalone" in text
    assert "3.14.7" in text
    assert "20260901" in text


def test_install_ps1_recipe() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    assert "MyInvocation.MyCommand.Path" in text
    assert "Set-Location" in text
    assert "pyproject.toml" in text
    assert "requirements.txt" in text
    assert "-m venv" in text
    assert "pip install -r requirements.txt" in text
    assert ".local\\bin" in text or r".local\bin" in text
    assert "Path" in text
    assert ".env.example" in text
    assert 'Test-Path -Path ".env"' in text
    assert "uv sync" not in text
    assert "--group dev" not in text
    assert "pre-commit install" not in text
    assert "astral.sh/uv" not in text
    assert "python-build-standalone" in text
    assert "3.14.7" in text
    assert "20260901" in text


def test_requirements_txt_is_runtime_export() -> None:
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert "uv export --frozen --no-dev --no-hashes" in text
    assert "-e ." in text
    assert "httpx" in text
    assert "pytest" not in text
    assert "pre-commit" not in text
