import json
from collections.abc import Sequence

from red_alert.models import AttemptResult, RunReport


def mask_secrets(text: str, secrets: Sequence[str]) -> str:
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


def format_summary(report: RunReport) -> str:
    asr_percent = f"{report.asr * 100:.0f}%"
    lines = [
        f"scenario: {report.scenario}",
        f"target: {report.target}",
        f"successful: {report.successful_count}/{report.total_count}",
        f"ASR: {asr_percent}",
    ]
    for attempt in report.attempts:
        status = "success" if attempt.success else "failure"
        extra = _attempt_tail(attempt)
        line = f"attempt {attempt.attempt_index}: {status}"
        if extra:
            line = f"{line}  {extra}"
        lines.append(line)
    return "\n".join(lines)


def format_report(report: RunReport, *, secrets: Sequence[str]) -> str:
    return mask_secrets(format_summary(report), secrets)


def format_json_report(
    report: RunReport, *, secrets: Sequence[str], include_failed: bool = False
) -> str:
    payload = {
        "scenario": report.scenario,
        "target": report.target,
        "successful": report.successful_count,
        "total": report.total_count,
        "asr": report.asr,
        "traces": [
            {
                "attempt_index": attempt.attempt_index,
                "session_a": attempt.session_a,
                "session_b": attempt.session_b,
                "steps": [step.model_dump() for step in attempt.steps],
            }
            for attempt in report.attempts
            if include_failed or attempt.success
        ],
    }
    return mask_secrets(json.dumps(payload, ensure_ascii=False, indent=2, default=str), secrets)


def _attempt_tail(attempt: AttemptResult) -> str:
    if not attempt.steps:
        return ""
    last = attempt.steps[-1]
    if last.error:
        return f"{last.name} {last.error}"
    return last.name
