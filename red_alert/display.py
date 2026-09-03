import json
from collections.abc import Sequence

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from red_alert.models import AttackStep, AttemptResult, RunReport
from red_alert.report import mask_secrets


class AttackProgress:
    def __init__(self, console: Console, attempts: int) -> None:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.fields[phase]}"),
            BarColumn(bar_width=28),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        self._attempts = attempts
        self._task_id: TaskID | None = None

    def __enter__(self) -> "AttackProgress":
        self._progress.start()
        self._task_id = self._progress.add_task(
            "attack",
            total=self._attempts,
            phase="Ожидание",
        )
        return self

    def __exit__(self, *exc: object) -> None:
        self._progress.stop()

    def on_step(self, attempt_index: int, step: AttackStep) -> None:
        if self._task_id is None:
            return
        actor = f" · {step.actor}" if step.actor else ""
        self._progress.update(
            self._task_id,
            phase=f"Попытка {attempt_index}/{self._attempts} · {step.name}{actor}",
        )

    def on_attempt_done(self) -> None:
        if self._task_id is None:
            return
        self._progress.advance(self._task_id)


def print_debug_step(
    console: Console,
    attempt_index: int,
    step: AttackStep,
    secrets: Sequence[str],
) -> None:
    status = step.error or (f"HTTP {step.status_code}" if step.status_code else "ok")
    actor = step.actor or "-"
    console.print(
        f"[bold yellow]debug[/] attempt {attempt_index} · {step.name} · {actor} · {status}"
    )
    if step.url:
        console.print(f"  url: {mask_secrets(step.url, secrets)}")
    if step.request_body is not None:
        console.print(mask_secrets(_pretty_json(step.request_body), secrets))
    if step.response_body is not None:
        console.print(mask_secrets(_pretty_json(step.response_body), secrets))
    console.print()


def _pretty_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def print_summary(console: Console, report: RunReport) -> None:
    asr_percent = f"{report.asr * 100:.0f}%"
    asr_style = "bold green" if report.successful_count else "bold red"
    table = Table(title="Red Alert", show_header=False, box=None, padding=(0, 2))
    table.add_row("scenario", report.scenario)
    table.add_row("target", report.target)
    table.add_row("successful", f"{report.successful_count}/{report.total_count}")
    table.add_row(Text("ASR", style=asr_style), Text(asr_percent, style=asr_style))
    console.print(table)
    console.print()
    for attempt in report.attempts:
        console.print(_attempt_line(attempt))
    console.print()
    console.print(f"ASR: {asr_percent}")
    console.print(f"successful: {report.successful_count}/{report.total_count}")


def _attempt_line(attempt: AttemptResult) -> Text:
    if attempt.success:
        line = Text.assemble(
            ("  ✓ ", "bold green"),
            (f"attempt {attempt.attempt_index}: success", "green"),
        )
        if attempt.steps:
            line.append(f"  {attempt.steps[-1].name}", style="dim")
        return line
    last = attempt.steps[-1] if attempt.steps else None
    detail = ""
    if last is not None:
        detail = f"  {last.name}"
        if last.error:
            detail = f"{detail} {last.error}"
    return Text.assemble(
        ("  ✗ ", "bold red"),
        (f"attempt {attempt.attempt_index}: failure", "red"),
        (detail, "red"),
    )
