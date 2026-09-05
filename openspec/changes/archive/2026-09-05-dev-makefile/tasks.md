## 1. Makefile

- [x] 1.1 Добавить корневой `Makefile`: `help` по умолчанию, цели `setup`, `keys`, `langfuse-up`, `langfuse-down`, `test`, `lint`, `check`, `attack`.
- [x] 1.2 `setup` делает `uv sync --group dev`, `pre-commit install` и копирует `.env.example` только если `.env` нет. `langfuse-down` без `-v`. `attack` пробрасывает `ARGS`.

## 2. Тесты и документация

- [x] 2.1 Написать автотест: `make help` код 0 и печатает все имена целей; рецепты `setup`/`keys`/`langfuse-down`/`attack` содержат нужные команды. Не вызывать Docker и не запускать `make test` из теста.
- [x] 2.2 Обновить `README.md` и `ARCHITECTURE.md`; прогнать pytest, ruff и `openspec validate dev-makefile --strict`.
- [x] 2.3 Добавить `ty` в `lint`, цель `fmt` (`ruff format`), зависимость `ty` в dev-группу; обновить тесты и README.
