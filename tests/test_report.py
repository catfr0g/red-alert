from red_alert.models import AttemptResult, RunReport
from red_alert.report import format_report, mask_secrets


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
