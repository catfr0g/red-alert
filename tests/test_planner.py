import json
from collections.abc import Callable

import httpx

from red_alert.planner import (
    RETRY_NUDGE,
    LlmConfig,
    OpenAICompatPlanner,
    PlannerContext,
    _assistant_text,
    _clean_payload,
    build_planner_messages,
)


def _context(
    *,
    last_finalize: object | None = None,
    prior_notes: str = "",
) -> PlannerContext:
    return PlannerContext(
        goal="цель YDEX",
        inject_index=1,
        last_payload=None,
        last_assistant=None,
        last_finalize=last_finalize,
        prior_notes=prior_notes,
        examples=("пример",),
    )


def test_planner_prompt_includes_feedback() -> None:
    messages = build_planner_messages(
        _context(
            last_finalize={"facts": [{"scope": "user"}]},
            prior_notes="попытка 1: success=False",
        )
    )
    user = messages[1]["content"]
    assert "цель YDEX" in user
    assert "scope" in user
    assert "попытка 1" in user
    assert messages[0]["role"] == "system"
    assert "YDEX" not in messages[0]["content"]


def test_clean_payload_strips_fences_and_quotes() -> None:
    assert _clean_payload("```\nhello\n```") == "hello"
    assert _clean_payload('"hello"') == "hello"


def test_openai_planner_posts_to_configured_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "  payload YDEX  "}}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    planner = OpenAICompatPlanner(
        LlmConfig(
            api_key="sk-planner",
            base_url="https://openrouter.ai/api/v1",
            model="openai/gpt-5-mini",
            max_tokens=128,
        ),
        client,
    )
    turn = planner.plan(_context(last_finalize={"facts": [{"scope": "user"}]}))
    assert turn.error is None
    assert turn.payload == "payload YDEX"
    assert seen[0].url.host == "openrouter.ai"
    assert seen[0].url.path.endswith("/chat/completions")
    assert seen[0].headers["Authorization"] == "Bearer sk-planner"
    body = json.loads(seen[0].content.decode("utf-8"))
    assert body["model"] == "openai/gpt-5-mini"
    assert body["max_tokens"] == 128
    assert "цель YDEX" in body["messages"][1]["content"]


def _planner(handler: Callable[[httpx.Request], httpx.Response]) -> OpenAICompatPlanner:
    return OpenAICompatPlanner(
        LlmConfig(
            api_key="sk-planner",
            base_url="https://llm.test/v1",
            model="demo",
            max_tokens=16,
        ),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_assistant_text_reads_parts_and_output_text() -> None:
    assert (
        _assistant_text(
            {"choices": [{"message": {"content": [{"type": "text", "text": "part YDEX"}]}}]}
        )
        == "part YDEX"
    )
    assert _assistant_text({"output_text": "out YDEX", "choices": []}) == "out YDEX"


def test_openai_planner_retries_empty_then_uses_text() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={"choices": [{"message": {"content": ""}}]})
        body = json.loads(request.content.decode("utf-8"))
        assert body["messages"][-1]["content"] == RETRY_NUDGE
        return httpx.Response(200, json={"choices": [{"message": {"content": "retry YDEX"}}]})

    turn = _planner(handler).plan(_context())
    assert turn.error is None
    assert turn.payload == "retry YDEX"
    assert calls["n"] == 2


def test_openai_planner_falls_back_to_example_after_empty() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": ""}}]})

    turn = _planner(handler).plan(_context())
    assert turn.error is None
    assert turn.payload == "пример"


def test_openai_planner_empty_without_example_is_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "   "}}]})

    context = PlannerContext(
        goal="цель YDEX",
        inject_index=1,
        last_payload=None,
        last_assistant=None,
        last_finalize=None,
        prior_notes="",
        examples=(),
    )
    turn = _planner(handler).plan(context)
    assert turn.error == "пустой ответ планировщика"
    assert turn.payload == ""
