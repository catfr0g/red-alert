"""Выпускает API-ключи тестового стенда и пишет их в .env."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import httpx

from red_alert.config import UsageError, merged_environ, normalize_target

DEFAULT_TARGET = "http://localhost:8600"
DEFAULT_KEYCLOAK_URL = "http://localhost:8180"
DEFAULT_REALM = "genai-stand"
DEFAULT_CLIENT_ID = "streamlit-ui"
DEFAULT_CLIENT_SECRET = "streamlit-ui-secret"
DEFAULT_USERS = ("client1001", "client1002")
KEY_RE = re.compile(r"sk-genai-[A-Za-z0-9_-]{20,}")
HTTP_TIMEOUT_SECONDS = 30.0


class StandSetupError(Exception):
    """Сбой Keycloak, стенда или разбора ответа."""


@dataclass(frozen=True)
class SetupConfig:
    target: str
    keycloak_url: str
    realm: str
    client_id: str
    client_secret: str
    users: tuple[str, ...]
    password: str | None
    env_file: Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fetch_stand_keys",
        description="Выпускает API-ключи стенда и пишет их в .env",
    )
    parser.add_argument("--target", help="Базовый URL agent-api")
    parser.add_argument("--keycloak-url", help="Базовый URL Keycloak")
    parser.add_argument("--realm", help="Realm Keycloak")
    parser.add_argument("--client-id", help="Client id для password grant")
    parser.add_argument("--client-secret", help="Client secret для password grant")
    parser.add_argument("--users", help="Логины через запятую, минимум два")
    parser.add_argument("--password", help="Общий пароль; иначе пароль равен логину")
    parser.add_argument("--env-file", default=".env", help="Куда писать ключи")
    return parser


def parse_users(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return DEFAULT_USERS
    users = tuple(part.strip() for part in raw.split(",") if part.strip())
    if len(users) < 2:
        raise UsageError("Нужны минимум два пользователя: атакующий и жертва")
    return users


def env_name_for(index: int, username: str) -> str:
    if index == 0:
        return "RED_ALERT_API_KEY"
    if index == 1:
        return "RED_ALERT_VICTIM_API_KEY"
    return f"RED_ALERT_USER_{username}_API_KEY"


def key_prefix(raw_key: str) -> str:
    return raw_key[:15] + "…"


def extract_key(html: str) -> str | None:
    matches = KEY_RE.findall(html)
    if not matches:
        return None
    return max(matches, key=len)


def _picked(
    flag: str | None,
    environ: Mapping[str, str],
    env_name: str,
    default: str,
    label: str,
) -> str:
    if flag is not None:
        value = flag.strip()
    else:
        value = (environ.get(env_name) or default).strip()
    if not value:
        raise UsageError(f"Нужен {label}")
    return value


def resolve_setup_config(
    args: argparse.Namespace,
    environ: Mapping[str, str],
) -> SetupConfig:
    target = _picked(args.target, environ, "RED_ALERT_TARGET", DEFAULT_TARGET, "--target")
    keycloak_url = _picked(
        args.keycloak_url,
        environ,
        "RED_ALERT_KEYCLOAK_URL",
        DEFAULT_KEYCLOAK_URL,
        "--keycloak-url",
    )
    realm = _picked(args.realm, environ, "RED_ALERT_KEYCLOAK_REALM", DEFAULT_REALM, "--realm")
    client_id = _picked(
        args.client_id,
        environ,
        "RED_ALERT_KEYCLOAK_CLIENT_ID",
        DEFAULT_CLIENT_ID,
        "--client-id",
    )
    client_secret = _picked(
        args.client_secret,
        environ,
        "RED_ALERT_KEYCLOAK_CLIENT_SECRET",
        DEFAULT_CLIENT_SECRET,
        "--client-secret",
    )
    raw_users = args.users if args.users is not None else environ.get("RED_ALERT_STAND_USERS")
    users = parse_users(raw_users)
    if args.password is not None:
        password = args.password
        if not password:
            raise UsageError("Нужен непустой --password")
    else:
        raw_password = environ.get("RED_ALERT_STAND_PASSWORD")
        password = raw_password if raw_password else None
    env_file = Path(args.env_file)
    if args.env_file is not None and not str(args.env_file).strip():
        raise UsageError("Нужен --env-file")
    return SetupConfig(
        target=normalize_target(target),
        keycloak_url=keycloak_url.rstrip("/"),
        realm=realm,
        client_id=client_id,
        client_secret=client_secret,
        users=users,
        password=password,
        env_file=env_file,
    )


def token_url(keycloak_url: str, realm: str) -> str:
    return f"{keycloak_url}/realms/{realm}/protocol/openid-connect/token"


def fetch_token(
    client: httpx.Client,
    config: SetupConfig,
    username: str,
) -> str:
    password = config.password if config.password is not None else username
    try:
        response = client.post(
            token_url(config.keycloak_url, config.realm),
            data={
                "grant_type": "password",
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "username": username,
                "password": password,
            },
        )
    except httpx.HTTPError as exc:
        raise StandSetupError(f"Keycloak недоступен для {username}") from exc
    if response.status_code >= 400:
        raise StandSetupError(
            f"Keycloak отказал пользователю {username}: HTTP {response.status_code}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise StandSetupError(f"Keycloak вернул не JSON для {username}") from exc
    token = payload.get("access_token")
    if not token or not isinstance(token, str):
        raise StandSetupError(f"Keycloak не вернул access_token для {username}")
    return token


def create_api_key(client: httpx.Client, config: SetupConfig, username: str, token: str) -> str:
    try:
        response = client.post(
            f"{config.target}/keys",
            headers={"X-Forwarded-Access-Token": token},
        )
    except httpx.HTTPError as exc:
        raise StandSetupError(f"Стенд недоступен для {username}") from exc
    if response.status_code >= 400:
        raise StandSetupError(f"Стенд отказал пользователю {username}: HTTP {response.status_code}")
    raw_key = extract_key(response.text)
    if not raw_key:
        raise StandSetupError(f"Стенд не вернул ключ для {username}")
    return raw_key


def upsert_env(path: Path, updates: Mapping[str, str]) -> None:
    example = path.with_name(".env.example")
    if path.is_file():
        text = path.read_text(encoding="utf-8")
    elif example.is_file():
        text = example.read_text(encoding="utf-8")
    else:
        text = ""
    remaining = dict(updates)
    new_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, _ = stripped.partition("=")
            key = key.strip()
            if key in remaining:
                new_lines.append(f"{key}={remaining.pop(key)}")
                continue
        new_lines.append(line)
    if remaining:
        if new_lines and new_lines[-1] != "":
            new_lines.append("")
        for key, value in remaining.items():
            new_lines.append(f"{key}={value}")
    payload = "\n".join(new_lines)
    if payload and not payload.endswith("\n"):
        payload += "\n"
    elif not payload:
        payload = ""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)


def issue_keys(client: httpx.Client, config: SetupConfig) -> dict[str, str]:
    issued: dict[str, str] = {}
    for username in config.users:
        token = fetch_token(client, config, username)
        issued[username] = create_api_key(client, config, username, token)
    return issued


def print_summary(
    config: SetupConfig,
    issued: Mapping[str, str],
    out: TextIO,
) -> None:
    for index, username in enumerate(config.users):
        name = env_name_for(index, username)
        out.write(f"{username} -> {name} ({key_prefix(issued[username])})\n")
    out.write(f"Записано: {config.env_file}\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    http_client: httpx.Client | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    argv = list(sys.argv[1:] if argv is None else argv)
    env: Mapping[str, str] = merged_environ() if environ is None else environ
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return 2 if code is None else int(code)

    try:
        config = resolve_setup_config(args, env)
    except UsageError as exc:
        print(str(exc), file=err)
        return 2

    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=HTTP_TIMEOUT_SECONDS)
    try:
        issued = issue_keys(client, config)
        updates = {
            env_name_for(index, username): issued[username]
            for index, username in enumerate(config.users)
        }
        upsert_env(config.env_file, updates)
    except StandSetupError as exc:
        print(str(exc), file=err)
        return 1
    finally:
        if owns_client:
            client.close()

    print_summary(config, issued, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
