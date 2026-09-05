## ADDED Requirements

### Requirement: Корневой Makefile со списком целей

СИСТЕМА ДОЛЖНА (MUST) содержать `Makefile` в корне репозитория. Запуск `make` без аргументов печатает список целей и завершается с кодом 0. В списке есть `setup`, `keys`, `langfuse-up`, `langfuse-down`, `test`, `lint`, `fmt`, `check` и `attack`.

#### Scenario: make без аргументов

- **WHEN** пользователь выполняет `make` в корне репозитория
- **THEN** процесс завершается с кодом 0 и в выводе есть имена `setup`, `keys`, `langfuse-up`, `langfuse-down`, `test`, `lint`, `fmt`, `check`, `attack`

### Requirement: Цель setup готовит среду uv

СИСТЕМА ДОЛЖНА (MUST) в цели `setup` выполнить `uv sync --group dev` и установить git-хуки pre-commit. Если файла `.env` нет, скопировать `.env.example` в `.env`. Существующий `.env` не перезаписывать.

#### Scenario: Рецепт setup содержит sync и хуки

- **WHEN** просматривают рецепт цели `setup`
- **THEN** в нём есть `uv sync --group dev` и `pre-commit install`

### Requirement: Цель keys выпускает ключи стенда

СИСТЕМА ДОЛЖНА (MUST) в цели `keys` запустить `script/fetch_stand_keys.py` через `uv run python`.

#### Scenario: Рецепт keys вызывает скрипт

- **WHEN** просматривают рецепт цели `keys`
- **THEN** в нём есть `script/fetch_stand_keys.py`

### Requirement: Цели Langfuse поднимают и опускают локальный compose

СИСТЕМА ДОЛЖНА (MUST) в `langfuse-up` вызывать `docker compose up -d`, а в `langfuse-down` — `docker compose down` без флага `-v`. Эти цели не управляют инвестиционным стендом.

#### Scenario: Рецепт остановки без удаления томов

- **WHEN** просматривают рецепт цели `langfuse-down`
- **THEN** в нём есть `docker compose down` и нет `-v`

### Requirement: Проверки и атака остаются обёртками

СИСТЕМА ДОЛЖНА (MUST) в `test` вызывать `uv run pytest`, в `lint` — `uv run ruff check .` и `uv run ty check`, в `fmt` — `uv run ruff format .`, в `check` — сначала lint, затем test, в `attack` — `uv run red-alert attack` с дополнительными аргументами из `ARGS`.

#### Scenario: Рецепт attack пробрасывает ARGS

- **WHEN** просматривают рецепт цели `attack`
- **THEN** в нём есть `red-alert attack` и `ARGS`

#### Scenario: Рецепт lint включает ruff и ty

- **WHEN** просматривают рецепт цели `lint`
- **THEN** в нём есть `ruff check` и `ty check`

#### Scenario: Рецепт fmt вызывает ruff format

- **WHEN** просматривают рецепт цели `fmt`
- **THEN** в нём есть `ruff format`
