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
        f"auth_mode: {report.auth_mode}",
        f"isolation: {report.isolation}",
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


def report_payload(report: RunReport, *, include_failed: bool = False) -> dict:
    return {
        "scenario": report.scenario,
        "target": report.target,
        "auth_mode": report.auth_mode,
        "isolation": report.isolation,
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


def format_json_report(
    report: RunReport, *, secrets: Sequence[str], include_failed: bool = False
) -> str:
    payload = report_payload(report, include_failed=include_failed)
    return mask_secrets(json.dumps(payload, ensure_ascii=False, indent=2, default=str), secrets)


def format_json_reports(
    reports: Sequence[RunReport],
    *,
    secrets: Sequence[str],
    include_failed: bool = False,
) -> str:
    if len(reports) == 1:
        return format_json_report(reports[0], secrets=secrets, include_failed=include_failed)
    successful = sum(item.successful_count for item in reports)
    total = sum(item.total_count for item in reports)
    payload = {
        "target": reports[0].target if reports else "",
        "successful": successful,
        "total": total,
        "asr": successful / total if total else 0.0,
        "runs": [report_payload(item, include_failed=include_failed) for item in reports],
    }
    return mask_secrets(json.dumps(payload, ensure_ascii=False, indent=2, default=str), secrets)


def _attempt_tail(attempt: AttemptResult) -> str:
    if not attempt.steps:
        return ""
    last = attempt.steps[-1]
    if last.error:
        return f"{last.name} {last.error}"
    return last.name
