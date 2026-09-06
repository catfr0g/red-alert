from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "install.sh"
INSTALL_PS1 = ROOT / "install.ps1"
REQUIREMENTS = ROOT / "requirements.txt"
CODEX_ASSETS = ROOT / "red_alert" / "codex_harness"
CODEX_PROFILE = CODEX_ASSETS / "red-alert-harness.config.toml"
CODEX_REQUIREMENTS = CODEX_ASSETS / "requirements.toml"


def test_install_scripts_exist() -> None:
    assert INSTALL_SH.is_file()
    assert INSTALL_PS1.is_file()
    assert REQUIREMENTS.is_file()
    assert CODEX_PROFILE.is_file()
    assert CODEX_REQUIREMENTS.is_file()


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
    assert "red-alert-harness.config.toml" not in text


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
    assert "red-alert-harness.config.toml" not in text


def test_codex_harness_profile_is_restricted() -> None:
    import tomllib

    profile = tomllib.loads(CODEX_PROFILE.read_text(encoding="utf-8"))
    assert profile["default_permissions"] == "red-alert-harness"
    assert profile["approval_policy"] == "never"
    assert profile["web_search"] == "disabled"
    permissions = profile["permissions"]["red-alert-harness"]
    assert permissions["filesystem"]["glob_scan_max_depth"] == 12
    assert permissions["filesystem"][":root"] == "deny"
    assert permissions["filesystem"][":minimal"] == "read"
    workspace = permissions["filesystem"][":workspace_roots"]
    assert workspace["."] == "read"
    assert workspace[".env"] == "deny"
    assert workspace[".env.*"] == "deny"
    assert workspace["**/.env"] == "deny"
    assert workspace["**/.env.*"] == "deny"
    assert workspace[".git"] == "deny"
    assert workspace["**/.git"] == "deny"
    assert workspace["node_modules"] == "deny"
    assert workspace[".venv"] == "deny"
    assert workspace["__pycache__"] == "deny"
    assert permissions["network"]["enabled"] is False


def test_codex_requirements_allows_harness_profile() -> None:
    import tomllib

    requirements = tomllib.loads(CODEX_REQUIREMENTS.read_text(encoding="utf-8"))
    assert requirements["default_permissions"] == ":workspace"
    allowed = requirements["allowed_permission_profiles"]
    assert allowed[":read-only"] is True
    assert allowed[":workspace"] is True
    assert allowed[":danger-full-access"] is True
    assert allowed["red-alert-harness"] is True


def test_requirements_txt_is_runtime_export() -> None:
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert "uv export --frozen --no-dev --no-hashes" in text
    assert "-e ." in text
    assert "httpx" in text
    assert "pytest" not in text
    assert "pre-commit" not in text
