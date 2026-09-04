import httpx

from red_alert.judge import JudgeContext, JudgeTurn
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


class ScriptedJudge:
    def __init__(self, verdicts: list[bool], *, url: str = PLANNER_URL) -> None:
        self.verdicts = list(verdicts)
        self.url = url
        self.contexts: list[JudgeContext] = []

    def judge(self, context: JudgeContext) -> JudgeTurn:
        self.contexts.append(context)
        if not self.verdicts:
            return JudgeTurn(
                success=False,
                request_body={},
                url=self.url,
                error="нет заготовленного вердикта",
            )
        verdict = self.verdicts.pop(0)
        text = str(verdict).lower()
        return JudgeTurn(
            success=verdict,
            request_body={
                "model": "scripted",
                "messages": [{"role": "user", "content": context.success_check}],
            },
            url=self.url,
            response=httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": text}}]},
            ),
        )
