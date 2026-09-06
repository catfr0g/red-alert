## MODIFIED Requirements

### Requirement: Корневой Makefile со списком целей

СИСТЕМА ДОЛЖНА (MUST) содержать `Makefile` в корне репозитория. Запуск `make` без аргументов печатает список целей и завершается с кодом 0. В списке есть `setup`, `keys`, `langfuse-up`, `langfuse-down`, `test`, `lint`, `fmt`, `check` и `attack`.

#### Scenario: make без аргументов

- **WHEN** пользователь выполняет `make` в корне репозитория
- **THEN** процесс завершается с кодом 0 и в выводе есть имена `setup`, `keys`, `langfuse-up`, `langfuse-down`, `test`, `lint`, `fmt`, `check`, `attack`

### Requirement: Цель keys выпускает ключи стенда

СИСТЕМА ДОЛЖНА (MUST) в цели `keys` вызывать `uv run python script/fetch_stand_keys.py` без дополнительных аргументов Makefile.

#### Scenario: make keys

- **WHEN** пользователь выполняет `make keys` при доступных Keycloak и agent-api
- **THEN** скрипт обновляет ключи стенда в `.env`
