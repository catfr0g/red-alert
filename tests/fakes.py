from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import httpx

from red_alert.dialogue import DialogueLog, DialogueTracer, DialogueTurn
from red_alert.models import AttemptResult
from red_alert.planner import PlannerContext, PlannerTurn
from red_alert.tracing import LangfuseError, attempt_tags

PLANNER_URL = "https://planner.test/v1/chat/completions"


class ScriptedPlanner:
    def __init__(self, texts: list[str], *, url: str = PLANNER_URL) -> None:
        self.texts = list(texts)
        self.url = url
        self.contexts: list[PlannerContext] = []

    def plan(self, context: PlannerContext) -> PlannerTurn:
        self.contexts.append(context)
        if not self.texts:
            return PlannerTurn(
                payload="",
                request_body={},
                url=self.url,
                error="нет заготовленного payload",
            )
        text = self.texts.pop(0)
        return PlannerTurn(
            payload=text,
            request_body={
                "model": "scripted",
                "messages": [{"role": "user", "content": context.goal}],
            },
            url=self.url,
            response=httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": text}}]},
            ),
        )


class RecordingSink:
    def __init__(self, *, ping_error: str | None = None, export_error: str | None = None) -> None:
        self.ping_error = ping_error
        self.export_error = export_error
        self.ping_calls = 0
        self.closed = False
        self.starts: list[dict] = []
        self.ticks = 0
        self.exports: list[dict] = []
        self.dialogue_events: list[dict] = []

    def ping(self) -> None:
        self.ping_calls += 1
        if self.ping_error:
            raise LangfuseError(self.ping_error)

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
    ) -> Iterator["_RecordingTrace"]:
        self.starts.append(
            {
                "scenario": scenario,
                "flow": flow,
                "vulnerability": vulnerability,
                "auth_mode": auth_mode,
                "attempt_index": attempt_index,
            }
        )
        yield _RecordingTrace(
            self,
            scenario=scenario,
            flow=flow,
            vulnerability=vulnerability,
            auth_mode=auth_mode,
            secrets=secrets,
        )

    def export_attempt(
        self,
        *,
        scenario: str,
        flow: str,
        vulnerability: str,
        auth_mode: str,
        attempt: AttemptResult,
        secrets: Sequence[str],
        dialogues: Sequence[dict] | None = None,
    ) -> None:
        if self.export_error:
            raise LangfuseError(self.export_error)
        self.exports.append(
            {
                "scenario": scenario,
                "flow": flow,
                "vulnerability": vulnerability,
                "auth_mode": auth_mode,
                "success": attempt.success,
                "tags": attempt_tags(
                    vulnerability=vulnerability,
                    success=attempt.success,
                    steps=attempt.steps,
                ),
                "score": attempt.success,
                "dialogues": list(dialogues or []),
            }
        )

    def close(self) -> None:
        self.closed = True


class _RecordingTrace:
    def __init__(
        self,
        sink: RecordingSink,
        *,
        scenario: str,
        flow: str,
        vulnerability: str,
        auth_mode: str,
        secrets: Sequence[str],
    ) -> None:
        self.invoke_config: dict[str, object] = {}
        self.dialogue: DialogueTracer = _RecordingDialogue(sink)
        self._sink = sink
        self._scenario = scenario
        self._flow = flow
        self._vulnerability = vulnerability
        self._auth_mode = auth_mode
        self._secrets = secrets

    def on_tick(self) -> None:
        self._sink.ticks += 1

    def complete(self, attempt: AttemptResult) -> None:
        self.dialogue.end_dialogue()
        self._sink.export_attempt(
            scenario=self._scenario,
            flow=self._flow,
            vulnerability=self._vulnerability,
            auth_mode=self._auth_mode,
            attempt=attempt,
            secrets=self._secrets,
            dialogues=self.dialogue.dialogues,
        )


class _RecordingDialogue(DialogueLog):
    def __init__(self, sink: RecordingSink) -> None:
        super().__init__()
        self._sink = sink

    @contextmanager
    def planner(self, *, messages: list[dict], model: str | None = None):
        turn = DialogueTurn()
        yield turn
        self._sink.dialogue_events.append(
            {
                "kind": "planner",
                "input": messages,
                "output": turn.output,
                "error": turn.error,
            }
        )

    @contextmanager
    def stand(self, *, user: str, actor: str, session_id: str):
        turn = DialogueTurn()
        yield turn
        self._sink.dialogue_events.append(
            {
                "kind": "stand",
                "actor": actor,
                "session_id": session_id,
                "input": [{"role": "user", "content": user}],
                "output": turn.output,
                "error": turn.error,
            }
        )

    @contextmanager
    def finalize(self, *, session_id: str):
        turn = DialogueTurn()
        yield turn
        self._sink.dialogue_events.append(
            {
                "kind": "finalize",
                "session_id": session_id,
                "output": turn.output,
                "error": turn.error,
            }
        )
