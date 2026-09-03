import json
from collections.abc import Sequence

from red_alert.models import RunReport


def mask_secrets(text: str, secrets: Sequence[str]) -> str:
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


def format_report(report: RunReport, *, secrets: Sequence[str]) -> str:
    asr_percent = f"{report.asr * 100:.0f}%"
    lines = [
        f"scenario: {report.scenario}",
        f"target: {report.target}",
        f"successful: {report.successful_count}/{report.total_count}",
        f"ASR: {asr_percent}",
    ]
    for attempt in report.attempts:
        status = "success" if attempt.success else "failure"
        lines.append("")
        lines.append(f"attempt {attempt.attempt_index}: {status}")
        for step in attempt.steps:
            lines.append(f"  step: {step.name}")
            if step.actor:
                lines.append(f"  actor: {step.actor}")
            lines.append(f"  {step.method} {step.url}")
            if step.request_body is not None:
                lines.append(f"  request: {_dump(step.request_body)}")
            if step.status_code is not None:
                lines.append(f"  status: {step.status_code}")
            if step.response_body is not None:
                lines.append(f"  response: {_dump(step.response_body)}")
            if step.error:
                lines.append(f"  error: {step.error}")
    return mask_secrets("\n".join(lines), secrets)


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
