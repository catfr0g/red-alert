from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import httpx
from rich.console import Console

from red_alert.attacks import AttackScenario, load_catalog_attacks, load_named_attack
from red_alert.config import (
    ISOLATION_OFF_WARNING,
    UsageError,
    merged_environ,
    resolve_config,
)
from red_alert.display import AttackProgress, print_debug_step, print_summaries
from red_alert.models import AttackStep, AttemptResult, RunReport
from red_alert.planner import LlmConfig, OpenAICompatPlanner
from red_alert.report import format_json_reports, mask_secrets
from red_alert.runner import run_attack
from red_alert.target import IsolateError
from red_alert.tracing import LangfuseError, TraceSink, build_sink

HTTP_TIMEOUT_SECONDS = 180.0


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="red-alert")
    subparsers = parser.add_subparsers(dest="command", required=True)
    attack = subparsers.add_parser("attack", help="Запустить сценарий атаки на стенд")
    attack.add_argument("--target", help="Базовый URL agent-api")
    attack.add_argument("--api-key", help="Bearer-ключ атакующего")
    attack.add_argument("--victim-api-key", help="Bearer-ключ другого пользователя стенда")
    attack.add_argument(
        "--scenario",
        help="Имя YAML или путь к файлу. Без флага — все атаки каталога",
    )
    attack.add_argument("--attacks-dir", help="Каталог с YAML-атаками")
    attack.add_argument(
        "--auth-mode",
        help="Режим стенда: vulnerable, protected или both",
    )
    attack.add_argument("--attempts", type=int, default=1, help="Число попыток каждого сценария")
    attack.add_argument(
        "--isolate",
        help="Изоляция попыток: on или off. По умолчанию on",
    )
    attack.add_argument(
        "--output",
        "-o",
        help="Записать JSON-трейсы успешных атак в UTF-8 файл",
    )
    attack.add_argument(
        "--debug",
        action="store_true",
        help="Полный лог всех шагов на stderr и traces всех попыток",
    )
    return parser


def _load_scenarios(scenario: str | None, attacks_dir: Path) -> list[AttackScenario]:
    if scenario:
        return [load_named_attack(scenario, attacks_dir)]
    return load_catalog_attacks(attacks_dir)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    http_client: httpx.Client | None = None,
    console: Console | None = None,
    progress_console: Console | None = None,
    trace_sink: TraceSink | None = None,
) -> int:
    _configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    env: Mapping[str, str] = merged_environ() if environ is None else environ
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return 2 if code is None else int(code)

    try:
        config = resolve_config(
            target=args.target,
            api_key=args.api_key,
            victim_api_key=args.victim_api_key,
            scenario=args.scenario,
            attempts=args.attempts,
            environ=env,
            debug=args.debug,
            attacks_dir=args.attacks_dir,
            auth_mode=args.auth_mode,
            isolation=args.isolate,
        )
        scenarios = _load_scenarios(config.scenario, config.attacks_dir)
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    out = console or Console()
    log = progress_console or Console(stderr=True)
    secrets = (
        config.api_key,
        config.victim_api_key,
        config.openai_api_key,
        config.langfuse_secret_key,
        config.langfuse_public_key,
    )

    current = [1]
    active_scenario: list[AttackScenario | None] = [None]
    active_auth: list[str] = [config.auth_modes[0]]

    def on_step(step: AttackStep) -> None:
        if config.debug:
            print_debug_step(log, current[0], step, secrets)
        elif progress is not None:
            progress.on_step(current[0], step)

    def mark_done(result: AttemptResult) -> None:
        if progress is not None:
            progress.on_attempt_done()
        current[0] += 1

    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=HTTP_TIMEOUT_SECONDS)
    owns_langfuse_client = False
    langfuse_client: httpx.Client | None = None
    if trace_sink is not None:
        sink = trace_sink
    elif config.langfuse_enabled:
        langfuse_client = httpx.Client(timeout=10.0)
        owns_langfuse_client = True
        sink = build_sink(config, langfuse_client, secrets)
    else:
        sink = build_sink(config, client, secrets)
    progress: AttackProgress | None = None
    try:
        if config.isolation == "off":
            print(ISOLATION_OFF_WARNING, file=sys.stderr)
        sink.ping()
        planner = OpenAICompatPlanner(
            LlmConfig(
                api_key=config.openai_api_key,
                base_url=config.openai_base_url,
                model=config.model,
                max_tokens=config.max_tokens,
            ),
            client,
        )

        def run_all() -> list[RunReport]:
            reports: list[RunReport] = []
            for scenario in scenarios:
                active_scenario[0] = scenario
                for auth_mode in config.auth_modes:
                    active_auth[0] = auth_mode
                    current[0] = 1
                    label = f"{scenario.name} · {auth_mode}"
                    if progress is not None:
                        progress.set_scenario(label)
                    if config.debug:
                        log.print(f"[bold yellow]debug[/] scenario {label}")
                    reports.append(
                        run_attack(
                            target=config.target,
                            api_key=config.api_key,
                            victim_api_key=config.victim_api_key,
                            scenario=scenario,
                            attempts=config.attempts,
                            http_client=client,
                            planner=planner,
                            auth_mode=auth_mode,
                            on_step=on_step,
                            on_attempt_done=mark_done,
                            sink=sink,
                            secrets=secrets,
                            isolation=config.isolation,
                        )
                    )
            return reports

        if config.debug:
            reports = run_all()
        else:
            first_label = f"{scenarios[0].name} · {config.auth_modes[0]}"
            with AttackProgress(
                log,
                config.attempts,
                first_label,
                total=config.attempts * len(scenarios) * len(config.auth_modes),
            ) as progress:
                reports = run_all()
        sink.close()
    except (LangfuseError, IsolateError) as exc:
        print(mask_secrets(str(exc), secrets), file=sys.stderr)
        return 1
    finally:
        if owns_langfuse_client and langfuse_client is not None:
            langfuse_client.close()
        if owns_client:
            client.close()

    print_summaries(out, reports)
    json_text = format_json_reports(reports, secrets=secrets, include_failed=config.debug)
    output = getattr(args, "output", None)
    if output:
        Path(output).write_text(json_text + "\n", encoding="utf-8")
        out.print(f"JSON: {output}")
    else:
        out.print(json_text)
    return 0
