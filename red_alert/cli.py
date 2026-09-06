from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import httpx
from rich.console import Console

from red_alert.analyzer import (
    CONTEXT_LIMIT,
    AnalyzerError,
    SourceAnalyzer,
    build_analyzer,
    codex_pretty_trace_path,
    resolve_analyzer_name,
)
from red_alert.attacks import (
    AttackScenario,
    apply_profile,
    load_catalog_attacks,
    load_named_template,
)
from red_alert.config import (
    ISOLATION_OFF_WARNING,
    UsageError,
    merged_environ,
    resolve_config,
)
from red_alert.display import AttackProgress, print_debug_step, print_skipped, print_summaries
from red_alert.judge import AttackJudge, OpenAICompatJudge
from red_alert.models import AttackStep, AttemptResult, RunReport
from red_alert.planner import LlmConfig, OpenAICompatPlanner
from red_alert.profile import SkippedScenario, StandProfile, dump_profile, load_profile
from red_alert.profile_target import ProfileTarget, profile_secret_values
from red_alert.report import format_json_reports, mask_secrets
from red_alert.runner import run_attack
from red_alert.target import ResetError
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
    attack.add_argument(
        "--scenario",
        help="Имя YAML или путь к файлу. Без флага — все атаки каталога",
    )
    attack.add_argument("--attacks-dir", help="Каталог с YAML-атаками")
    attack.add_argument("--profile", help="YAML-профиль цели")
    inspect = subparsers.add_parser("inspect", help="Разобрать исходники стенда и записать профиль")
    inspect.add_argument("path", help="Каталог исходников стенда")
    inspect.add_argument("--output", "-o", help="Куда записать StandProfile YAML")
    inspect.add_argument("--context", help="Дополнительный текстовый контекст для анализатора")
    inspect.add_argument(
        "--analyzer",
        choices=("heuristic", "llm", "harness"),
        help="backend анализа: heuristic, llm или harness (Codex)",
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


def _select_scenarios(
    scenario: str | None,
    attacks_dir: Path,
    profile: StandProfile,
) -> tuple[list[AttackScenario], list[SkippedScenario]]:
    if scenario:
        templates = [load_named_template(scenario, attacks_dir)]
        instances, skipped = apply_profile(templates, profile, override=True)
        if not instances:
            reason = skipped[0].reason if skipped else "не удалось собрать сценарий"
            raise UsageError(reason)
        return instances, []
    templates = load_catalog_attacks(attacks_dir)
    instances, skipped = apply_profile(templates, profile)
    if not instances:
        details = "; ".join(f"{item.name}: {item.reason}" for item in skipped) or "пусто"
        raise UsageError(f"После профиля не осталось атак. {details}")
    return instances, skipped


def _run_inspect(
    args: argparse.Namespace,
    *,
    environ: Mapping[str, str],
    http_client: httpx.Client | None,
    analyzer: SourceAnalyzer | None,
    console: Console | None,
) -> int:
    source = Path(args.path)
    if not source.is_dir():
        print(f"Нет каталога исходников: {source}", file=sys.stderr)
        return 2
    context_path = Path(args.context) if args.context else None
    context_text: str | None = None
    if context_path is not None:
        if not context_path.is_file():
            print(f"Нет файла контекста: {context_path}", file=sys.stderr)
            return 2
        try:
            context_text = context_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"Не удалось прочитать контекст {context_path}: {exc}", file=sys.stderr)
            return 2
        if len(context_text) > CONTEXT_LIMIT:
            print(
                f"Контекст больше {CONTEXT_LIMIT} символов: {context_path}",
                file=sys.stderr,
            )
            return 2
    name = resolve_analyzer_name(args.analyzer, dict(environ))
    owns_client = False
    client = http_client
    try:
        if analyzer is None:
            if name == "llm" and client is None:
                client = httpx.Client(timeout=HTTP_TIMEOUT_SECONDS)
                owns_client = True
            resolved = build_analyzer(
                name,
                environ=dict(environ),
                http_client=client,
                context_text=context_text,
                context_name=str(context_path) if context_path is not None else None,
            )
        else:
            resolved = analyzer
        profile = resolved.analyze(source).model_copy(
            update={"context": str(context_path) if context_path is not None else None}
        )
        output = Path(args.output) if args.output else Path.cwd() / "stand-profile.yaml"
        output.write_text(dump_profile(profile), encoding="utf-8")
        out = console or Console()
        out.print(f"Профиль: {output}")
        trace = codex_pretty_trace_path()
        if analyzer is None and name == "harness" and trace.is_file():
            out.print(f"Трассировка Codex: {trace}")
        return 0
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except AnalyzerError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if owns_client and client is not None:
            client.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    http_client: httpx.Client | None = None,
    console: Console | None = None,
    progress_console: Console | None = None,
    trace_sink: TraceSink | None = None,
    judge: AttackJudge | None = None,
    analyzer: SourceAnalyzer | None = None,
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

    if args.command == "inspect":
        return _run_inspect(
            args,
            environ=env,
            http_client=http_client,
            analyzer=analyzer,
            console=console,
        )

    try:
        config = resolve_config(
            scenario=args.scenario,
            attempts=args.attempts,
            environ=env,
            debug=args.debug,
            attacks_dir=args.attacks_dir,
            profile=args.profile,
            isolation=args.isolate,
        )
        profile = load_profile(Path(config.profile))
        scenarios, skipped = _select_scenarios(
            config.scenario,
            config.attacks_dir,
            profile,
        )
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    out = console or Console()
    log = progress_console or Console(stderr=True)
    bearer_names = {
        connection.bearer_env
        for scenario in scenarios
        for connection in (
            profile.runtime(scenario.name).target,
            profile.runtime(scenario.name).eval,
        )
        if connection.bearer_env
    }
    missing_bearers = sorted(name for name in bearer_names if name not in env)
    if missing_bearers:
        print("Не заданы env: " + ", ".join(missing_bearers), file=sys.stderr)
        return 2
    bearer_values = tuple(env[name] for name in sorted(bearer_names))
    runtime_secrets = tuple(
        dict.fromkeys(
            value
            for scenario in scenarios
            for value in profile_secret_values(profile, scenario.name, env)
        )
    )
    secrets = (
        *bearer_values,
        *runtime_secrets,
        config.openai_api_key,
        config.langfuse_secret_key,
        config.langfuse_public_key,
    )

    current = [1]

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
        for scenario in scenarios:
            ProfileTarget(profile, scenario.name, env, client)
        sink.ping()
        planner = OpenAICompatPlanner(
            LlmConfig(
                api_key=config.openai_api_key,
                base_url=config.attack_openai_base_url,
                model=config.attack_model,
                max_tokens=config.max_tokens,
            ),
            client,
        )
        resolved_judge = judge or OpenAICompatJudge(
            LlmConfig(
                api_key=config.openai_api_key,
                base_url=config.judge_openai_base_url,
                model=config.judge_model,
                max_tokens=config.max_tokens,
            )
        )

        def run_all() -> list[RunReport]:
            reports: list[RunReport] = []
            for scenario in scenarios:
                current[0] = 1
                if progress is not None:
                    progress.set_scenario(scenario.name)
                if config.debug:
                    log.print(f"[bold yellow]debug[/] scenario {scenario.name}")
                reports.append(
                    run_attack(
                        profile=profile,
                        environ=env,
                        scenario=scenario,
                        attempts=config.attempts,
                        http_client=client,
                        planner=planner,
                        judge=resolved_judge,
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
            first_label = scenarios[0].name
            with AttackProgress(
                log,
                config.attempts,
                first_label,
                total=config.attempts * len(scenarios),
            ) as progress:
                reports = run_all()
        sink.close()
    except (LangfuseError, ResetError) as exc:
        print(mask_secrets(str(exc), secrets), file=sys.stderr)
        return 1
    except UsageError as exc:
        print(mask_secrets(str(exc), secrets), file=sys.stderr)
        return 2
    finally:
        if owns_langfuse_client and langfuse_client is not None:
            langfuse_client.close()
        if owns_client:
            client.close()

    print_skipped(out, skipped)
    print_summaries(out, reports)
    json_text = format_json_reports(
        reports, secrets=secrets, include_failed=config.debug, skipped=skipped
    )
    output = getattr(args, "output", None)
    if output:
        Path(output).write_text(json_text + "\n", encoding="utf-8")
        out.print(f"JSON: {output}")
    else:
        out.print(json_text)
    return 0
