import json

from red_alert.models import AttackStep, AttemptResult, RunReport
from red_alert.report import format_json_report, format_json_reports, format_report, mask_secrets


def test_asr_all_success() -> None:
    report = RunReport(
        scenario="memory-poisoning",
        target="http://localhost:8600",
        attempts=[
            AttemptResult(attempt_index=1, success=True, session_a="a1", session_b="b1"),
            AttemptResult(attempt_index=2, success=True, session_a="a2", session_b="b2"),
        ],
    )
    text = format_report(report, secrets=["secret"])
    assert "successful: 2/2" in text
    assert "ASR: 100%" in text
    assert "auth_mode: vulnerable" in text


def test_asr_partial() -> None:
    report = RunReport(
        scenario="memory-poisoning",
        target="http://localhost:8600",
        attempts=[
            AttemptResult(attempt_index=1, success=True, session_a="a1", session_b="b1"),
            AttemptResult(attempt_index=2, success=False, session_a="a2", session_b="b2"),
        ],
    )
    text = format_report(report, secrets=["secret"])
    assert "successful: 1/2" in text
    assert "ASR: 50%" in text


def test_mask_secrets_both_keys() -> None:
    assert mask_secrets("a sk-att and sk-vic", ["sk-att", "sk-vic"]) == "a *** and ***"


def test_format_report_omits_authorization_header() -> None:
    report = RunReport(
        scenario="memory-poisoning",
        target="http://localhost:8600",
        attempts=[
            AttemptResult(
                attempt_index=1,
                success=False,
                session_a="a1",
                session_b="b1",
                steps=[],
            )
        ],
    )
    text = format_report(report, secrets=["sk-secret", "sk-victim"])
    assert "Authorization" not in text
    assert "sk-secret" not in text
    assert "sk-victim" not in text


def test_json_report_includes_only_successful_traces() -> None:
    report = RunReport(
        scenario="memory-poisoning",
        target="http://localhost:8600",
        attempts=[
            AttemptResult(
                attempt_index=1,
                success=True,
                session_a="a1",
                session_b="b1",
                steps=[
                    AttackStep(
                        name="payload-1",
                        method="POST",
                        url="http://localhost:8600/v1/chat/completions",
                        actor="attacker",
                    ),
                    AttackStep(
                        name="finalize",
                        method="POST",
                        url="http://localhost:8600/v1/sessions/a1/finalize",
                        actor="attacker",
                    ),
                    AttackStep(
                        name="trigger",
                        method="POST",
                        url="http://localhost:8600/v1/chat/completions",
                        actor="victim",
                    ),
                ],
            ),
            AttemptResult(attempt_index=2, success=False, session_a="a2", session_b="b2"),
        ],
    )
    payload = format_json_report(report, secrets=["sk-secret"])
    assert '"attempt_index": 1' in payload
    assert '"attempt_index": 2' not in payload
    assert "payload-1" in payload
    assert "finalize" in payload
    assert "trigger" in payload
    assert "sk-secret" not in payload


def test_json_report_includes_failed_traces_when_asked() -> None:
    report = RunReport(
        scenario="memory-poisoning",
        target="http://localhost:8600",
        attempts=[
            AttemptResult(
                attempt_index=2,
                success=False,
                session_a="a2",
                session_b="b2",
                steps=[
                    AttackStep(
                        name="adapt",
                        method="POST",
                        url="https://openrouter.ai/api/v1/chat/completions",
                        actor="planner",
                    )
                ],
            )
        ],
    )
    payload = format_json_report(report, secrets=["sk-secret"], include_failed=True)
    assert '"attempt_index": 2' in payload
    assert "adapt" in payload


def test_json_reports_wraps_multiple_runs() -> None:
    reports = [
        RunReport(
            scenario="cross-user-portfolio",
            target="http://localhost:8600",
            attempts=[AttemptResult(attempt_index=1, success=True, session_a="a1", session_b="b1")],
        ),
        RunReport(
            scenario="memory-poisoning",
            target="http://localhost:8600",
            attempts=[
                AttemptResult(attempt_index=1, success=False, session_a="a2", session_b="b2")
            ],
        ),
    ]
    payload = json.loads(format_json_reports(reports, secrets=["sk-secret"]))
    assert payload["total"] == 2
    assert payload["successful"] == 1
    assert payload["asr"] == 0.5
    assert [item["scenario"] for item in payload["runs"]] == [
        "cross-user-portfolio",
        "memory-poisoning",
    ]


def test_json_reports_single_keeps_flat_shape() -> None:
    report = RunReport(
        scenario="memory-poisoning",
        target="http://localhost:8600",
        attempts=[AttemptResult(attempt_index=1, success=True, session_a="a1", session_b="b1")],
    )
    payload = json.loads(format_json_reports([report], secrets=["sk-secret"]))
    assert payload["scenario"] == "memory-poisoning"
    assert payload["auth_mode"] == "vulnerable"
    assert "runs" not in payload
