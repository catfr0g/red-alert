from io import StringIO
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from red_alert.config import UsageError
from script.fetch_stand_keys import (
    env_name_for,
    extract_key,
    key_prefix,
    main,
    parse_users,
    upsert_env,
)

ATTACKER_KEY = "sk-genai-attacker-key-value-0001"
VICTIM_KEY = "sk-genai-victim-key-value-00002xx"
EXTRA_KEY = "sk-genai-extra-user-key-value-0003"
CLIENT_SECRET = "streamlit-ui-secret"


class SetupMock:
    def __init__(
        self,
        keys: dict[str, str] | None = None,
        *,
        fail_token: set[str] | None = None,
        fail_keys: set[str] | None = None,
    ) -> None:
        self.keys = keys or {
            "client1001": ATTACKER_KEY,
            "client1002": VICTIM_KEY,
            "client1003": EXTRA_KEY,
        }
        self.fail_token = fail_token or set()
        self.fail_keys = fail_keys or set()
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.rstrip("/")
        if path.endswith("/token"):
            form = parse_qs(request.content.decode())
            username = (form.get("username") or [""])[0]
            if username in self.fail_token:
                return httpx.Response(401, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"access_token": f"token-{username}"})
        if path.endswith("/keys"):
            token = request.headers.get("x-forwarded-access-token", "")
            username = token.removeprefix("token-")
            if username in self.fail_keys:
                return httpx.Response(401, text="unauthorized")
            raw_key = self.keys[username]
            html = (
                "<p>apiKey: sk-genai-...</p>"
                f"<b>Сохраните ключ сейчас</b><code>{raw_key}</code>"
                f"<td><code>{raw_key[:15]}</code></td>"
            )
            return httpx.Response(200, text=html)
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def run_script(
    tmp_path: Path,
    mock: SetupMock,
    *extra: str,
    environ: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    env_file = tmp_path / ".env"
    stdout = StringIO()
    stderr = StringIO()
    code = main(
        ["--env-file", str(env_file), *extra],
        environ=environ or {},
        http_client=mock.client(),
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_parse_users_default() -> None:
    assert parse_users(None) == ("client1001", "client1002")


def test_parse_users_requires_two() -> None:
    with pytest.raises(UsageError, match="два"):
        parse_users("client1001")


def test_env_names() -> None:
    assert env_name_for(0, "client1001") == "RED_ALERT_API_KEY"
    assert env_name_for(1, "client1002") == "RED_ALERT_VICTIM_API_KEY"
    assert env_name_for(2, "client1003") == "RED_ALERT_USER_client1003_API_KEY"


def test_extract_key_picks_full_key_not_prefix() -> None:
    html = f"<code>{ATTACKER_KEY[:15]}</code><code>{ATTACKER_KEY}</code>apiKey: sk-genai-..."
    assert extract_key(html) == ATTACKER_KEY


def test_success_writes_two_keys(tmp_path: Path) -> None:
    mock = SetupMock()
    code, out, err = run_script(tmp_path, mock)
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert code == 0
    assert err == ""
    assert f"RED_ALERT_API_KEY={ATTACKER_KEY}" in text
    assert f"RED_ALERT_VICTIM_API_KEY={VICTIM_KEY}" in text
    assert "client1001 -> RED_ALERT_API_KEY" in out
    assert key_prefix(ATTACKER_KEY) in out
    assert any(request.url.path.endswith("/token") for request in mock.requests)
    assert any(request.url.path.endswith("/keys") for request in mock.requests)


def test_three_users_write_extra_var(tmp_path: Path) -> None:
    mock = SetupMock()
    code, _, _ = run_script(tmp_path, mock, "--users", "client1001,client1002,client1003")
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert code == 0
    assert f"RED_ALERT_USER_client1003_API_KEY={EXTRA_KEY}" in text


def test_one_user_exits_2_without_http(tmp_path: Path) -> None:
    mock = SetupMock()
    code, _, err = run_script(tmp_path, mock, "--users", "client1001")
    assert code == 2
    assert "два" in err
    assert mock.requests == []
    assert not (tmp_path / ".env").exists()


def test_empty_target_exits_2_without_http(tmp_path: Path) -> None:
    mock = SetupMock()
    code, _, err = run_script(tmp_path, mock, "--target", "")
    assert code == 2
    assert "--target" in err
    assert mock.requests == []


def test_flag_overrides_env_target(tmp_path: Path) -> None:
    mock = SetupMock()
    code, _, _ = run_script(
        tmp_path,
        mock,
        "--target",
        "http://new.example:8600",
        environ={"RED_ALERT_TARGET": "http://old.example:8600"},
    )
    assert code == 0
    key_hosts = {
        request.url.host for request in mock.requests if request.url.path.endswith("/keys")
    }
    assert key_hosts == {"new.example"}


def test_password_defaults_to_username(tmp_path: Path) -> None:
    mock = SetupMock()
    code, _, _ = run_script(tmp_path, mock)
    assert code == 0
    token_bodies = [
        parse_qs(request.content.decode())
        for request in mock.requests
        if request.url.path.endswith("/token")
    ]
    passwords = {body["username"][0]: body["password"][0] for body in token_bodies}
    assert passwords == {"client1001": "client1001", "client1002": "client1002"}


def test_keeps_unrelated_env_values(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OPENAI_API_KEY=sk-planner\nRED_ALERT_API_KEY=sk-old\n# comment\n",
        encoding="utf-8",
    )
    mock = SetupMock()
    code, _, _ = run_script(tmp_path, mock)
    text = env_file.read_text(encoding="utf-8")
    assert code == 0
    assert "OPENAI_API_KEY=sk-planner" in text
    assert "# comment" in text
    assert f"RED_ALERT_API_KEY={ATTACKER_KEY}" in text
    assert "sk-old" not in text


def test_second_user_failure_leaves_env_untouched(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    original = "OPENAI_API_KEY=sk-planner\nRED_ALERT_API_KEY=sk-old\n"
    env_file.write_text(original, encoding="utf-8")
    mock = SetupMock(fail_keys={"client1002"})
    code, _, err = run_script(tmp_path, mock)
    assert code == 1
    assert "client1002" in err
    assert env_file.read_text(encoding="utf-8") == original


def test_copies_env_example_when_missing(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        "OPENAI_API_KEY=from-example\nRED_ALERT_API_KEY=sk-placeholder\n",
        encoding="utf-8",
    )
    mock = SetupMock()
    code, _, _ = run_script(tmp_path, mock)
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert code == 0
    assert "OPENAI_API_KEY=from-example" in text
    assert f"RED_ALERT_API_KEY={ATTACKER_KEY}" in text


def test_secrets_are_masked(tmp_path: Path) -> None:
    mock = SetupMock()
    code, out, err = run_script(
        tmp_path,
        mock,
        "--client-secret",
        CLIENT_SECRET,
        "--password",
        "shared-pass",
    )
    combined = out + err
    assert code == 0
    assert ATTACKER_KEY not in combined
    assert VICTIM_KEY not in combined
    assert CLIENT_SECRET not in combined
    assert "shared-pass" not in combined


def test_keycloak_error_hides_password(tmp_path: Path) -> None:
    mock = SetupMock(fail_token={"client1001"})
    code, out, err = run_script(tmp_path, mock, "--password", "shared-pass")
    combined = out + err
    assert code == 1
    assert "HTTP 401" in err
    assert "shared-pass" not in combined


def test_upsert_env_appends_missing_keys(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("MODEL=openai/gpt-5-mini\n", encoding="utf-8")
    upsert_env(path, {"RED_ALERT_API_KEY": ATTACKER_KEY})
    text = path.read_text(encoding="utf-8")
    assert "MODEL=openai/gpt-5-mini" in text
    assert f"RED_ALERT_API_KEY={ATTACKER_KEY}" in text
