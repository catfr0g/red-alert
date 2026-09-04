from rich.console import Console

from red_alert.display import AttackProgress
from red_alert.models import AttackStep


def test_progress_bar_shows_scenario() -> None:
    console = Console(quiet=True)
    step = AttackStep(
        name="adapt",
        method="POST",
        url="https://llm.example/v1/chat/completions",
        actor="planner",
    )
    with AttackProgress(console, attempts=3, scenario="memory-poisoning") as progress:
        waiting = progress._progress.tasks[0].fields["phase"]
        assert waiting == "memory-poisoning · ожидание"
        progress.on_step(1, step)
        phase = progress._progress.tasks[0].fields["phase"]
        progress.set_scenario("cross-user-portfolio")
        switched = progress._progress.tasks[0].fields["phase"]
    assert phase == "memory-poisoning · попытка 1/3 · adapt · planner"
    assert switched == "cross-user-portfolio · ожидание"
