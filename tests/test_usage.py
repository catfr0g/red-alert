from red_alert.usage import (
    UsageRecord,
    parse_codex_jsonl,
    parse_openai_usage,
    parse_run_usage,
    usage_payload,
)


def test_parse_openai_usage_without_cost() -> None:
    prompt, completion = parse_openai_usage(
        {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7},
        }
    )
    assert prompt == 11
    assert completion == 7


def test_parse_openai_usage_missing_is_zero() -> None:
    assert parse_openai_usage({"choices": []}) == (0, 0)
    assert parse_openai_usage("nope") == (0, 0)


def test_parse_run_usage_reads_input_output() -> None:
    class _Usage:
        input_tokens = 4
        output_tokens = 2

    class _Result:
        def usage(self) -> _Usage:
            return _Usage()

    assert parse_run_usage(_Result()) == (4, 2)


def test_merge_keeps_role_and_model() -> None:
    first = UsageRecord(role="planner", model="vllm/qwen").plus_tokens(10, 3)
    second = UsageRecord(role="planner", model="vllm/qwen").plus_tokens(5, 1)
    judge = UsageRecord(role="judge", model="openai/gpt-5.4-mini").plus_tokens(8, 2)
    payload = usage_payload([first, second, judge])
    assert payload["planner"] == {
        "model": "vllm/qwen",
        "input_tokens": 15,
        "output_tokens": 4,
    }
    assert payload["judge"] == {
        "model": "openai/gpt-5.4-mini",
        "input_tokens": 8,
        "output_tokens": 2,
    }


def test_same_model_keeps_inspect_separate() -> None:
    inspect = UsageRecord(role="inspect", model="shared").plus_tokens(20, 1)
    planner = UsageRecord(role="planner", model="shared").plus_tokens(9, 4)
    payload = usage_payload([inspect, planner])
    inspect_usage = payload["inspect"]
    planner_usage = payload["planner"]
    assert isinstance(inspect_usage, dict)
    assert isinstance(planner_usage, dict)
    assert inspect_usage["input_tokens"] == 20
    assert planner_usage["input_tokens"] == 9


def test_parse_codex_jsonl_sums_turns() -> None:
    raw = "\n".join(
        [
            '{"type":"thread.started","model":"gpt-5.3-codex"}',
            '{"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":10,"reasoning_output_tokens":5}}',
            "not-json",
            '{"type":"turn.completed","usage":{"input_tokens":20,"output_tokens":2}}',
        ]
    )
    record = parse_codex_jsonl(raw)
    assert record.role == "inspect"
    assert record.model == "gpt-5.3-codex"
    assert record.input_tokens == 120
    assert record.output_tokens == 17
