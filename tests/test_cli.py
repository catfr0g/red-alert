import json
from io import StringIO
from pathlib import Path

import httpx
from rich.console import Console

from red_alert.cli import main
from tests.fakes import ScriptedJudge
from tests.test_config import LLM_ENV


def _files(tmp_path: Path, *, bearer_env: str | None = "AGENT_TOKEN") -> tuple[Path, Path]:
    attack = tmp_path / "custom.yaml"
    attack.write_text(
        "\n".join(
            (
                "name: custom",
                "flow: probe",
                "vulnerability: test",
                "goal: test target",
                "payloads:",
                "  - payload",
                "success_check: leaked",
                "max_injects: 1",
            )
        ),
        encoding="utf-8",
    )
    profile = tmp_path / "profile.yaml"
    bearer_line = f"      bearer_env: {bearer_env}" if bearer_env else "      bearer_env: null"
    profile.write_text(
        "\n".join(
            (
                "source: custom",
                "capabilities: {}",
                "bindings:",
                "  custom:",
                "    target:",
                "      endpoint: https://agent.test/v1/chat/completions",
                bearer_line,
                "      model: custom-agent",
                "      custom_body:",
                "        session_id: ${target_session_id}",
                "    eval:",
                "      inherit: target",
                "    persist: null",
            )
        ),
        encoding="utf-8",
    )
    return attack, profile


class CliMock:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "llm.test":
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "generated payload"}}]},
            )
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "target response"}}]},
        )


def _env(profile: Path, **extra: str) -> dict[str, str]:
    return {
        **LLM_ENV,
        "OPENAI_BASE_URL": "https://llm.test/v1",
        "RED_ALERT_PROFILE": str(profile),
        **extra,
    }


def test_attack_requires_explicit_profile(tmp_path: Path) -> None:
    attack, _profile = _files(tmp_path)
    assert main(["attack", "--scenario", str(attack)], environ=LLM_ENV) == 2


def test_attack_runs_only_from_profile_runtime(tmp_path: Path) -> None:
    attack, profile = _files(tmp_path)
    mock = CliMock()
    output = tmp_path / "report.json"
    with mock.client() as client:
        code = main(
            [
                "attack",
                "--scenario",
                str(attack),
                "--profile",
                str(profile),
                "--output",
                str(output),
            ],
            environ=_env(profile, AGENT_TOKEN="agent-secret"),
            http_client=client,
            judge=ScriptedJudge([True]),
            console=Console(file=StringIO()),
            progress_console=Console(file=StringIO()),
        )

    assert code == 0
    request = next(item for item in mock.requests if item.url.host == "agent.test")
    body = json.loads(request.content)
    assert request.headers["Authorization"] == "Bearer agent-secret"
    assert body["model"] == "custom-agent"
    assert body["session_id"].startswith("ra-target-")
    assert json.loads(output.read_text(encoding="utf-8"))["target"] == (
        "https://agent.test/v1/chat/completions"
    )


def test_missing_profile_bearer_fails_before_http(tmp_path: Path) -> None:
    attack, profile = _files(tmp_path)
    mock = CliMock()
    with mock.client() as client:
        code = main(
            ["attack", "--scenario", str(attack), "--profile", str(profile)],
            environ=_env(profile),
            http_client=client,
            judge=ScriptedJudge([True]),
        )
    assert code == 2
    assert mock.requests == []


def test_removed_target_specific_flags_are_rejected(tmp_path: Path) -> None:
    attack, profile = _files(tmp_path, bearer_env=None)
    code = main(
        [
            "attack",
            "--scenario",
            str(attack),
            "--profile",
            str(profile),
            "--target-kind",
            "invest",
        ],
        environ=_env(profile),
    )
    assert code == 2
