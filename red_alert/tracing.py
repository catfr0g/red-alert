from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlparse

import httpx
from langfuse import Langfuse, propagate_attributes
from langfuse.langchain import CallbackHandler
from langfuse.types import TraceContext
from opentelemetry import context as otel_context

from red_alert.config import AppConfig
from red_alert.dialogue import (
    DialogueLog,
    DialogueTracer,
    DialogueTurn,
    NullDialogue,
    graph_node_input,
    graph_node_output,
    is_hidden_graph_run,
    user_message,
)
from red_alert.models import AttackStep, AttemptResult
from red_alert.report import mask_secrets

PLANNER_ACTOR = "planner"
CHAT_PATH = "/v1/chat/completions"
FINALIZE_PATH = "/v1/sessions/finalize"
FINALIZE_RE = re.compile(r"^/v1/sessions/[^/]+/finalize/?$")
RESET_PATH = "/v1/memory/reset"


class LangfuseError(Exception):
    """Langfuse is enabled but unreachable or rejected the export."""


class GraphCallbackHandler(CallbackHandler):
    """CallbackHandler, который в UI кладёт короткий ход диалога, а не AttemptState."""

    def __init__(
        self,
        *,
        public_key: str | None = None,
        trace_context: TraceContext | None = None,
    ) -> None:
        super().__init__(public_key=public_key, trace_context=trace_context)
        self._node_names: dict = {}
        self._hidden_runs: set = set()

    def on_chain_start(self, serialized, inputs, *, run_id, **kwargs):
        name = self.get_langchain_run_name(serialized, **kwargs)
        if is_hidden_graph_run(name):
            self._hidden_runs.add(run_id)
            return None
        self._node_names[run_id] = name
        return super().on_chain_start(
            serialized, graph_node_input(name, inputs), run_id=run_id, **kwargs
        )

    def on_chain_end(self, outputs, *, run_id, parent_run_id=None, **kwargs):
        if run_id in self._hidden_runs:
            self._hidden_runs.discard(run_id)
            return None
        name = self._node_names.pop(run_id, "")
        raw_inputs = kwargs.get("inputs")
        viewed = graph_node_input(name, raw_inputs) if raw_inputs is not None else raw_inputs
        return super().on_chain_end(
            graph_node_output(name, outputs),
            run_id=run_id,
            parent_run_id=parent_run_id,
            inputs=viewed,
        )

    def on_chain_error(self, error, *, run_id, parent_run_id=None, tags=None, **kwargs):
        if run_id in self._hidden_runs:
            self._hidden_runs.discard(run_id)
            return None
        name = self._node_names.pop(run_id, "")
        raw_inputs = kwargs.get("inputs")
        viewed = graph_node_input(name, raw_inputs) if raw_inputs is not None else raw_inputs
        return super().on_chain_error(
            error,
            run_id=run_id,
            parent_run_id=parent_run_id,
            tags=tags,
            inputs=viewed,
        )


class LangfuseDialogue(DialogueLog):
    def __init__(self, sdk: Langfuse, *, isolate_context: TraceContext | None = None) -> None:
        super().__init__()
        self._sdk = sdk
        self._isolate_context = isolate_context

    @contextmanager
    def planner(self, *, messages: list[dict], model: str | None = None) -> Iterator[DialogueTurn]:
        with self._observation(
            name="planner",
            as_type="generation",
            input=messages,
            model=model,
            metadata={"agent": "planner"},
        ) as turn:
            yield turn

    @contextmanager
    def stand(self, *, user: str, actor: str, session_id: str) -> Iterator[DialogueTurn]:
        with self._observation(
            name="stand",
            as_type="generation",
            input=[user_message(user)],
            metadata={"agent": "stand", "actor": actor, "session_id": session_id},
        ) as turn:
            yield turn

    @contextmanager
    def persist(self, *, session_id: str) -> Iterator[DialogueTurn]:
        with self._observation(
            name="persist",
            as_type="span",
            input={"session_id": session_id, "action": "persist"},
            metadata={"dialogue": "attacker", "session_id": session_id},
        ) as turn:
            yield turn

    @contextmanager
    def isolate(self) -> Iterator[DialogueTurn]:
        with self._observation(
            name="isolate",
            as_type="span",
            input={"action": "isolate"},
            metadata={"capability": "isolate"},
            trace_context=self._isolate_context,
        ) as turn:
            yield turn

    @contextmanager
    def _observation(
        self,
        *,
        name: str,
        as_type: str,
        input: object,
        metadata: dict,
        model: str | None = None,
        trace_context: TraceContext | None = None,
    ) -> Iterator[DialogueTurn]:
        kwargs: dict = {
            "name": name,
            "as_type": as_type,
            "input": input,
            "metadata": metadata,
        }
        if as_type == "generation" and model:
            kwargs["model"] = model
        if trace_context is not None:
            kwargs["trace_context"] = trace_context
        try:
            cm = self._sdk.start_as_current_observation(**kwargs)
        except Exception as exc:
            raise LangfuseError(f"Не удалось записать trace в Langfuse: {exc}") from exc
        turn = DialogueTurn()
        with cm as obs:
            yield turn
            update: dict = {"output": turn.output}
            if turn.model:
                update["model"] = turn.model
            if turn.error:
                update["level"] = "ERROR"
                update["status_message"] = turn.error
            try:
                obs.update(**update)
            except Exception as exc:
                raise LangfuseError(f"Не удалось записать trace в Langfuse: {exc}") from exc


class GraphTrace(Protocol):
    invoke_config: dict[str, object]
    dialogue: DialogueTracer

    def on_tick(self) -> None: ...

    def complete(self, attempt: AttemptResult) -> None: ...


class TraceSink(Protocol):
    def ping(self) -> None: ...

    def trace_attempt(
        self,
        *,
        scenario: str,
        flow: str,
        vulnerability: str,
        auth_mode: str,
        attempt_index: int,
        secrets: Sequence[str],
        isolation: str = "on",
    ) -> AbstractContextManager[GraphTrace]: ...

    def close(self) -> None: ...


class _NoopTrace:
    def __init__(self) -> None:
        self.invoke_config: dict[str, object] = {}
        self.dialogue: DialogueTracer = NullDialogue()

    def on_tick(self) -> None:
        return

    def complete(self, attempt: AttemptResult) -> None:
        self.dialogue.end_dialogue()


class NullSink:
    def ping(self) -> None:
        return

    @contextmanager
    def trace_attempt(
        self,
        *,
        scenario: str,
        flow: str,
        vulnerability: str,
        auth_mode: str,
        attempt_index: int,
        secrets: Sequence[str],
        isolation: str = "on",
    ) -> Iterator[_NoopTrace]:
        yield _NoopTrace()

    def close(self) -> None:
        return


class _LangfuseTrace:
    def __init__(
        self,
        sink: LangfuseSink,
        handler: CallbackHandler,
        *,
        scenario: str,
        flow: str,
        vulnerability: str,
        auth_mode: str,
        attempt_index: int,
        secrets: Sequence[str],
        isolation: str,
        trace_id: str,
        isolate_context: TraceContext | None = None,
    ) -> None:
        self.invoke_config: dict[str, object] = {
            "callbacks": [handler],
            "run_name": f"{scenario}:{attempt_index}",
            "metadata": {"langfuse_tags": [f"vulnerability:{vulnerability}"]},
        }
        self.dialogue: DialogueTracer = LangfuseDialogue(sink._sdk, isolate_context=isolate_context)
        self._sink = sink
        self._trace_id = trace_id
        self._scenario = scenario
        self._flow = flow
        self._vulnerability = vulnerability
        self._auth_mode = auth_mode
        self._isolation = isolation
        self._secrets = secrets

    def on_tick(self) -> None:
        self._sink.flush()

    def complete(self, attempt: AttemptResult) -> None:
        self.dialogue.end_dialogue()
        trace_id = self._trace_id
        if not trace_id:
            raise LangfuseError("Не удалось записать trace в Langfuse: нет trace_id")
        self._sink.finalize_trace(
            trace_id=trace_id,
            tags=attempt_tags(
                vulnerability=self._vulnerability,
                success=attempt.success,
                steps=attempt.steps,
                isolation=self._isolation,
            ),
            success=attempt.success,
            metadata={
                "scenario": self._scenario,
                "flow": self._flow,
                "auth_mode": self._auth_mode,
                "isolation": self._isolation,
                "attempt_index": attempt.attempt_index,
                "session_a": attempt.session_a,
                "session_b": attempt.session_b,
            },
            dialogues=self.dialogue.dialogues,
            secrets=self._secrets,
        )


class LangfuseSink:
    def __init__(
        self,
        *,
        public_key: str,
        secret_key: str,
        base_url: str,
        http_client: httpx.Client,
        secrets: Sequence[str] = (),
    ) -> None:
        self._public_key = public_key
        self._secret_key = secret_key
        self._base_url = base_url.rstrip("/")
        self._http = http_client
        self._secrets = tuple(item for item in secrets if item)
        try:
            self._sdk = Langfuse(
                public_key=public_key,
                secret_key=secret_key,
                base_url=self._base_url,
                httpx_client=http_client,
                tracing_enabled=True,
                flush_at=1,
                flush_interval=0.5,
                mask=self.mask_data,
            )
        except Exception as exc:
            raise LangfuseError(f"Langfuse недоступен: {exc}") from exc

    def mask_data(self, *, data: object, **_kwargs: object) -> object:
        return _masked(data, self._secrets)

    def ping(self) -> None:
        health = self._request("GET", "/api/public/health", auth=False)
        if health.status_code >= 400:
            raise LangfuseError(f"Langfuse недоступен: HTTP {health.status_code}")
        projects = self._request("GET", "/api/public/projects", auth=True)
        if projects.status_code in {401, 403}:
            raise LangfuseError("Langfuse отклонил ключи")
        if projects.status_code >= 400 and projects.status_code != 404:
            raise LangfuseError(f"Langfuse недоступен: HTTP {projects.status_code}")

    @contextmanager
    def trace_attempt(
        self,
        *,
        scenario: str,
        flow: str,
        vulnerability: str,
        auth_mode: str,
        attempt_index: int,
        secrets: Sequence[str],
        isolation: str = "on",
    ) -> Iterator[_LangfuseTrace]:
        merged = tuple(dict.fromkeys([*self._secrets, *[item for item in secrets if item]]))
        attempt_name = f"{scenario}:{attempt_index}"
        metadata = {
            "scenario": scenario,
            "flow": flow,
            "auth_mode": auth_mode,
            "isolation": isolation,
            "attempt_index": attempt_index,
        }
        try:
            with (
                _fresh_otel_context(),
                propagate_attributes(
                    trace_name=attempt_name,
                    tags=[f"vulnerability:{vulnerability}", f"isolation:{isolation}"],
                    metadata=metadata,
                ),
                self._attempt_root(
                    name=attempt_name,
                    scenario=scenario,
                    attempt_index=attempt_index,
                    metadata=metadata,
                ) as root,
            ):
                trace_context = _trace_context_of(root)
                try:
                    handler = GraphCallbackHandler(
                        public_key=self._public_key,
                        trace_context=trace_context,
                    )
                except Exception as exc:
                    raise LangfuseError(f"Langfuse недоступен: {exc}") from exc
                yield _LangfuseTrace(
                    self,
                    handler,
                    scenario=scenario,
                    flow=flow,
                    vulnerability=vulnerability,
                    auth_mode=auth_mode,
                    attempt_index=attempt_index,
                    secrets=merged,
                    isolation=isolation,
                    trace_id=trace_context["trace_id"],
                    isolate_context=trace_context,
                )
        finally:
            self.flush()

    def finalize_trace(
        self,
        *,
        trace_id: str,
        tags: Sequence[str],
        success: bool,
        metadata: dict,
        dialogues: Sequence[dict] | None = None,
        secrets: Sequence[str],
    ) -> None:
        now = datetime.now(UTC).isoformat()
        replay = list(dialogues or [])
        events = [
            _event(
                "trace-create",
                now,
                {
                    "id": trace_id,
                    "timestamp": now,
                    "name": f"{metadata['scenario']}:{metadata['attempt_index']}",
                    "tags": list(tags),
                    "metadata": _masked(metadata, secrets),
                    "input": _masked(replay, secrets),
                    "output": _masked(replay, secrets),
                },
            ),
            _event(
                "score-create",
                now,
                {
                    "id": uuid.uuid4().hex,
                    "traceId": trace_id,
                    "name": "attack_success",
                    "value": 1 if success else 0,
                    "dataType": "BOOLEAN",
                },
            ),
        ]
        response = self._request("POST", "/api/public/ingestion", auth=True, json={"batch": events})
        if response.status_code >= 400:
            raise LangfuseError(
                f"Не удалось записать trace в Langfuse: HTTP {response.status_code}"
            )
        errors = _ingestion_errors(response)
        if errors:
            raise LangfuseError(f"Не удалось записать trace в Langfuse: {errors}")
        self.flush()

    def flush(self) -> None:
        try:
            self._sdk.flush()
        except Exception as exc:
            raise LangfuseError(f"Не удалось записать trace в Langfuse: {exc}") from exc

    def close(self) -> None:
        self.flush()
        try:
            self._sdk.shutdown()
        except Exception as exc:
            raise LangfuseError(f"Не удалось записать trace в Langfuse: {exc}") from exc

    @contextmanager
    def _attempt_root(
        self,
        *,
        name: str,
        scenario: str,
        attempt_index: int,
        metadata: dict,
    ) -> Iterator[object]:
        try:
            cm = self._sdk.start_as_current_observation(
                name=name,
                as_type="span",
                input={
                    "action": "attempt",
                    "scenario": scenario,
                    "attempt_index": attempt_index,
                },
                metadata=metadata,
            )
        except Exception as exc:
            raise LangfuseError(f"Не удалось записать trace в Langfuse: {exc}") from exc
        try:
            with cm as root:
                yield root
        except LangfuseError:
            raise
        except Exception as exc:
            raise LangfuseError(f"Не удалось записать trace в Langfuse: {exc}") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        auth: bool,
        json: object | None = None,
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        kwargs: dict = {}
        if auth:
            kwargs["auth"] = (self._public_key, self._secret_key)
        if json is not None:
            kwargs["json"] = json
        try:
            return self._http.request(method, url, **kwargs)
        except httpx.RequestError as exc:
            raise LangfuseError(f"Langfuse недоступен: {exc}") from exc


def build_sink(
    config: AppConfig,
    http_client: httpx.Client,
    secrets: Sequence[str] = (),
) -> TraceSink:
    if not config.langfuse_enabled:
        return NullSink()
    return LangfuseSink(
        public_key=config.langfuse_public_key,
        secret_key=config.langfuse_secret_key,
        base_url=config.langfuse_base_url,
        http_client=http_client,
        secrets=secrets,
    )


def stand_endpoint(url: str, actor: str | None) -> str | None:
    if actor == PLANNER_ACTOR:
        return None
    path = urlparse(url).path
    if path.endswith(CHAT_PATH):
        return CHAT_PATH
    if FINALIZE_RE.match(path) or path.endswith("/finalize"):
        return FINALIZE_PATH
    if path.rstrip("/").endswith(RESET_PATH) or path.endswith("/memory/reset"):
        return RESET_PATH
    return None


def attempt_tags(
    *,
    vulnerability: str,
    success: bool,
    steps: Sequence[AttackStep],
    isolation: str | None = None,
) -> list[str]:
    tags = [
        f"outcome:{'success' if success else 'failure'}",
        f"vulnerability:{vulnerability}",
    ]
    if isolation:
        tags.append(f"isolation:{isolation}")
    seen: set[str] = set()
    for step in steps:
        endpoint = stand_endpoint(step.url, step.actor)
        if endpoint is None or endpoint in seen:
            continue
        seen.add(endpoint)
        tags.append(f"endpoint:{endpoint}")
    return tags


@contextmanager
def _fresh_otel_context() -> Iterator[None]:
    token = otel_context.attach(otel_context.Context())
    try:
        yield
    finally:
        try:
            otel_context.detach(token)
        except Exception:
            pass


def _trace_context_of(root: object) -> TraceContext:
    trace_id = getattr(root, "trace_id", None)
    if not trace_id:
        raise LangfuseError("Не удалось записать trace в Langfuse: нет trace_id")
    context: TraceContext = {"trace_id": str(trace_id)}
    span_id = getattr(root, "id", None)
    if span_id:
        context["parent_span_id"] = str(span_id)
    return context


def _event(event_type: str, timestamp: str, body: dict) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "timestamp": timestamp,
        "body": body,
    }


def _masked(value: object, secrets: Sequence[str]) -> object:
    if value is None:
        return None
    if isinstance(value, str):
        return mask_secrets(value, secrets)
    text = mask_secrets(json.dumps(value, ensure_ascii=False, default=str), secrets)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _ingestion_errors(response: httpx.Response) -> object:
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    errors = payload.get("errors")
    if errors:
        return errors
    return None
