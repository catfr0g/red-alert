from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import httpx

from red_alert.config import DEFAULT_SCENARIO, UsageError, merged_environ, resolve_config
from red_alert.report import format_report
from red_alert.runner import run_attack

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
    attack.add_argument("--scenario", default=DEFAULT_SCENARIO, help="Имя сценария")
    attack.add_argument("--attempts", type=int, default=1, help="Число попыток для ASR")
    attack.add_argument(
        "--output",
        "-o",
        help="Записать отчёт в файл в UTF-8 (не через редирект оболочки)",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    http_client: httpx.Client | None = None,
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
        )
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=HTTP_TIMEOUT_SECONDS)
    try:
        report = run_attack(
            target=config.target,
            api_key=config.api_key,
            victim_api_key=config.victim_api_key,
            scenario_name=config.scenario,
            attempts=config.attempts,
            http_client=client,
        )
    finally:
        if owns_client:
            client.close()

    text = format_report(report, secrets=(config.api_key, config.victim_api_key))
    print(text)
    output = getattr(args, "output", None)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    return 0
