from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import fields, is_dataclass
from typing import Protocol


class DialogueTurn:
    def __init__(self) -> None:
        self.output: object | None = None
        self.error: str | None = None
        self.model: str | None = None

    def finish(
        self,
        *,
        output: object | None = None,
        error: str | None = None,
        model: str | None = None,
    ) -> None:
        self.output = output
        self.error = error
        self.model = model


class DialogueTracer(Protocol):
    dialogues: list[dict]

    def begin_dialogue(self, *, name: str, session_id: str) -> None: ...

    def end_dialogue(self) -> None: ...

    def add_message(self, role: str, content: str) -> None: ...

    def set_finalize(self, body: object) -> None: ...

    def planner(
        self, *, messages: list[dict], model: str | None = None
    ) -> AbstractContextManager[DialogueTurn]: ...

    def stand(
        self, *, user: str, actor: str, session_id: str
    ) -> AbstractContextManager[DialogueTurn]: ...

    def finalize(self, *, session_id: str) -> AbstractContextManager[DialogueTurn]: ...


class DialogueLog:
    def __init__(self) -> None:
        self.dialogues: list[dict] = []
        self._current: dict | None = None

    def begin_dialogue(self, *, name: str, session_id: str) -> None:
        self.end_dialogue()
        self._current = {"name": name, "session_id": session_id, "messages": []}

    def add_message(self, role: str, content: str) -> None:
        if self._current is None or not content:
            return
        self._current["messages"].append({"role": role, "content": content})

    def set_finalize(self, body: object) -> None:
        if self._current is not None:
            self._current["finalize"] = body

    def end_dialogue(self) -> None:
        if self._current is None:
            return
        self.dialogues.append(self._current)
        self._current = None


class NullDialogue(DialogueLog):
    @contextmanager
    def planner(self, *, messages: list[dict], model: str | None = None) -> Iterator[DialogueTurn]:
        yield DialogueTurn()

    @contextmanager
    def stand(self, *, user: str, actor: str, session_id: str) -> Iterator[DialogueTurn]:
        yield DialogueTurn()

    @contextmanager
    def finalize(self, *, session_id: str) -> Iterator[DialogueTurn]:
        yield DialogueTurn()


HIDDEN_GRAPH_RUNS = frozenset(
    {
        "after_adapt",
        "after_inject",
        "after_finalize",
        "ChannelWrite",
        "Branch",
        "_route",
        "__start__",
        "__end__",
    }
)


def is_hidden_graph_run(name: str) -> bool:
    """Развилки и служебные шаги LangGraph в Langfuse не нужны."""
    if name in {"adapt", "inject", "finalize", "trigger", "planner", "stand"}:
        return False
    if name in HIDDEN_GRAPH_RUNS:
        return True
    return name.startswith("after_") or name.startswith("Channel") or name.startswith("branch:")


def as_state_dict(value: object) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: getattr(value, item.name) for item in fields(value)}
    return {}


def graph_node_input(name: str, inputs: object) -> dict:
    state = as_state_dict(inputs)
    if name == "adapt":
        return {"agent": "planner", "inject": int(state.get("injects") or 0) + 1}
    if name == "inject":
        return {
            "dialogue": "attacker",
            "messages": [user_message(str(state.get("payload") or ""))],
        }
    if name == "finalize":
        return {
            "dialogue": "attacker",
            "session_id": state.get("session_a") or "",
            "action": "finalize",
        }
    if name == "trigger":
        return {"dialogue": "victim", "session_id": state.get("session_b") or ""}
    return {"attempt": state.get("attempt_index")}


def graph_node_output(name: str, outputs: object) -> dict:
    data = as_state_dict(outputs)
    error = data.get("error")
    if name == "adapt":
        return {"payload": data.get("payload") or "", "error": error}
    if name == "inject":
        return {
            "dialogue": "attacker",
            "messages": [assistant_message(str(data.get("last_assistant") or ""))],
            "error": error,
        }
    if name == "finalize":
        return {"usable_policy": bool(data.get("usable_policy")), "error": error}
    if name == "trigger":
        return {"success": bool(data.get("success")), "error": error}
    return {"success": data.get("success"), "error": error}


def user_message(content: str) -> dict[str, str]:
    return {"role": "user", "content": content}


def assistant_message(content: str) -> dict[str, str]:
    return {"role": "assistant", "content": content}


def finalize_view(body: object) -> object:
    if isinstance(body, dict) and "facts" in body:
        return {"facts": body.get("facts")}
    return body
