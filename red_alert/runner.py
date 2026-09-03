from collections.abc import Callable

import httpx

from red_alert.graph import OnStep, run_attempt
from red_alert.models import AttemptResult, RunReport
from red_alert.scenarios.memory_poisoning import MemoryPoisoningScenario
from red_alert.stand_client import StandClient

__all__ = ["run_attempt", "run_attack"]


def run_attack(
    *,
    target: str,
    api_key: str,
    victim_api_key: str,
    scenario_name: str,
    attempts: int,
    http_client: httpx.Client,
    on_step: OnStep | None = None,
    on_attempt_done: Callable[[AttemptResult], None] | None = None,
) -> RunReport:
    if scenario_name != "memory-poisoning":
        raise ValueError(f"Неизвестный сценарий: {scenario_name}")
    scenario = MemoryPoisoningScenario()
    attacker = StandClient(target, api_key, http_client)
    victim = StandClient(target, victim_api_key, http_client)
    results: list[AttemptResult] = []
    for index in range(1, attempts + 1):
        result = run_attempt(attacker, victim, scenario, index, on_step)
        results.append(result)
        if on_attempt_done is not None:
            on_attempt_done(result)
    return RunReport(scenario=scenario.name, target=target, attempts=results)
