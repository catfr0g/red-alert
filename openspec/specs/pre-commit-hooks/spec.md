## Purpose

Перед коммитом ruff, ty и pytest запускаются через `.pre-commit-config.yaml`, без самописных git-hook скриптов.

## Requirements

### Requirement: Конфиг pre-commit с ruff, ty и pytest

СИСТЕМА ДОЛЖНА (MUST) хранить в корне репозитория `.pre-commit-config.yaml`, который запускает ruff, ty и pytest через фреймворк pre-commit.

#### Scenario: Ruff берётся из официального хука

- **WHEN** читается `.pre-commit-config.yaml`
- **THEN** в нём есть репозиторий `astral-sh/ruff-pre-commit` и хук `ruff-check`

#### Scenario: Ty берётся из официального хука

- **WHEN** читается `.pre-commit-config.yaml`
- **THEN** в нём есть репозиторий `astral-sh/ty-pre-commit` и хук `ty`

#### Scenario: Pytest запускается pre-commit

- **WHEN** читается `.pre-commit-config.yaml`
- **THEN** в нём есть хук `pytest`, который вызывает `uv run pytest`

#### Scenario: Нет самописного git-hook скрипта

- **WHEN** проверяется способ установки хуков
- **THEN** проверки задаются только `.pre-commit-config.yaml`, без скриптов в `.githooks` или `.git/hooks` внутри репозитория
