"""Суммирует входные и выходные токены из JSON-отчётов red-alert attack."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from red_alert.usage import (
    UsageRecord,
    format_usage_lines,
    merge_usage,
    records_from_report_payload,
    total_tokens,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sum_attack_usage",
        description="Суммирует input/output токены из JSON-отчётов атаки",
    )
    parser.add_argument(
        "reports",
        nargs="+",
        type=Path,
        help="Файлы JSON от red-alert attack --output",
    )
    return parser


def load_report(path: Path) -> object:
    if not path.is_file():
        raise ValueError(f"Нет файла отчёта: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Не JSON: {path}") from exc


def collect_records(paths: Sequence[Path]) -> list[UsageRecord]:
    records: list[UsageRecord] = []
    for path in paths:
        records.extend(records_from_report_payload(load_report(path)))
    return merge_usage(records)


def format_totals(records: Sequence[UsageRecord]) -> str:
    lines = format_usage_lines(records)
    incoming, outgoing = total_tokens(records)
    lines.append(f"total: in={incoming} out={outgoing}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        records = collect_records(args.reports)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(format_totals(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
