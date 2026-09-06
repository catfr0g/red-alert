from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel

UsageRole = Literal["inspect", "planner", "judge"]
KNOWN_ROLES: tuple[UsageRole, ...] = ("inspect", "planner", "judge")


class UsageRecord(BaseModel):
    role: UsageRole
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    def plus_tokens(self, input_tokens: int, output_tokens: int, *, calls: int = 1) -> UsageRecord:
        return self.model_copy(
            update={
                "input_tokens": self.input_tokens + input_tokens,
                "output_tokens": self.output_tokens + output_tokens,
                "calls": self.calls + calls,
            }
        )


def parse_openai_usage(payload: object) -> tuple[int, int]:
    if not isinstance(payload, dict):
        return 0, 0
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return 0, 0
    return _as_int(usage.get("prompt_tokens")), _as_int(usage.get("completion_tokens"))


def parse_run_usage(result: object) -> tuple[int, int]:
    getter = getattr(result, "usage", None)
    usage = getter() if callable(getter) else getter
    if usage is None:
        return 0, 0
    for input_name, output_name in (
        ("input_tokens", "output_tokens"),
        ("request_tokens", "response_tokens"),
        ("prompt_tokens", "completion_tokens"),
    ):
        raw_in = _attr_or_key(usage, input_name)
        raw_out = _attr_or_key(usage, output_name)
        if raw_in is not None or raw_out is not None:
            return _as_int(raw_in), _as_int(raw_out)
    return 0, 0


def parse_codex_jsonl(text: str, *, role: UsageRole = "inspect") -> UsageRecord:
    model = "codex"
    record = UsageRecord(role=role, model=model)
    turns = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            event = json_object(line)
        except ValueError:
            continue
        found = _codex_model(event)
        if found:
            model = found
        if event.get("type") != "turn.completed":
            continue
        usage = event.get("usage")
        if not isinstance(usage, dict):
            turns += 1
            continue
        record = record.plus_tokens(
            _as_int(usage.get("input_tokens")),
            _as_int(usage.get("output_tokens")) + _as_int(usage.get("reasoning_output_tokens")),
        )
        turns += 1
    if record.calls == 0 and turns:
        record = record.model_copy(update={"calls": turns})
    return record.model_copy(update={"model": model})


def merge_usage(records: Sequence[UsageRecord]) -> list[UsageRecord]:
    merged: dict[tuple[str, str], UsageRecord] = {}
    order: list[tuple[str, str]] = []
    for item in records:
        key = (item.role, item.model)
        current = merged.get(key)
        if current is None:
            merged[key] = item
            order.append(key)
            continue
        merged[key] = current.plus_tokens(
            item.input_tokens, item.output_tokens, calls=item.calls or 1
        )
    return [merged[key] for key in order]


def usage_payload(records: Sequence[UsageRecord]) -> dict[str, object]:
    by_role: dict[str, list[dict[str, object]]] = {}
    for item in merge_usage(records):
        by_role.setdefault(item.role, []).append(
            {
                "model": item.model,
                "input_tokens": item.input_tokens,
                "output_tokens": item.output_tokens,
            }
        )
    payload: dict[str, object] = {}
    for role, items in by_role.items():
        payload[role] = items[0] if len(items) == 1 else items
    return payload


def records_from_usage_block(block: object) -> list[UsageRecord]:
    if not isinstance(block, dict):
        return []
    records: list[UsageRecord] = []
    for role in KNOWN_ROLES:
        item = block.get(role)
        if item is None:
            continue
        entries = item if isinstance(item, list) else [item]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            model = entry.get("model")
            records.append(
                UsageRecord(
                    role=role,
                    model=model.strip() if isinstance(model, str) and model.strip() else "unknown",
                    input_tokens=_as_int(entry.get("input_tokens")),
                    output_tokens=_as_int(entry.get("output_tokens")),
                    calls=1,
                )
            )
    return records


def records_from_report_payload(payload: object) -> list[UsageRecord]:
    if not isinstance(payload, dict):
        return []
    if "usage" in payload:
        return records_from_usage_block(payload.get("usage"))
    records: list[UsageRecord] = []
    runs = payload.get("runs")
    if isinstance(runs, list):
        for run in runs:
            if isinstance(run, dict):
                records.extend(records_from_usage_block(run.get("usage")))
    return records


def total_tokens(records: Sequence[UsageRecord]) -> tuple[int, int]:
    return (
        sum(item.input_tokens for item in records),
        sum(item.output_tokens for item in records),
    )


def format_usage_lines(records: Sequence[UsageRecord]) -> list[str]:
    payload = usage_payload(records)
    lines: list[str] = []
    for role in ("inspect", "planner", "judge"):
        item = payload.get(role)
        if item is None:
            continue
        entries = item if isinstance(item, list) else [item]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            lines.append(
                f"{role}: {entry['model']}  in={entry['input_tokens']} out={entry['output_tokens']}"
            )
    return lines


def json_object(line: str) -> dict:
    parsed = json.loads(line)
    if not isinstance(parsed, dict):
        raise ValueError("not an object")
    return parsed


def _codex_model(event: dict) -> str | None:
    for key in ("model",):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    item = event.get("item")
    if isinstance(item, dict):
        value = item.get("model")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _attr_or_key(value: object, name: str) -> object:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def _as_int(value: object) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


CODEX_MISSING_HINT = (
    "Codex CLI не найден (команда codex). Укажите --analyzer llm или --analyzer heuristic"
)
