from pydantic import BaseModel, Field


class AttackStep(BaseModel):
    name: str
    method: str
    url: str
    actor: str | None = None
    request_body: dict | None = None
    response_body: object | None = None
    status_code: int | None = None
    error: str | None = None


class AttemptResult(BaseModel):
    attempt_index: int
    success: bool
    session_a: str
    session_b: str
    steps: list[AttackStep] = Field(default_factory=list)


class RunReport(BaseModel):
    scenario: str
    target: str
    auth_mode: str = "vulnerable"
    isolation: str = "on"
    attempts: list[AttemptResult] = Field(default_factory=list)

    @property
    def successful_count(self) -> int:
        return sum(1 for attempt in self.attempts if attempt.success)

    @property
    def total_count(self) -> int:
        return len(self.attempts)

    @property
    def asr(self) -> float:
        if self.total_count == 0:
            return 0.0
        return self.successful_count / self.total_count
