import httpx

from red_alert.planner import PlannerContext, PlannerTurn

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
