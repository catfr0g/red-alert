## 1. Модель usage

- [x] 1.1 Добавить `UsageRecord` / агрегат: роль, модель, input_tokens, output_tokens, calls; разбор `usage.prompt_tokens` / `completion_tokens` без `cost`.
- [x] 1.2 Тесты парсера: OpenAI-ответ с usage без cost; ответ без usage → нули; сумма нескольких вызовов одной роли.

## 2. Attack: планировщик и судья

- [x] 2.1 Копить usage внутри `plan()` по всем ретраям; отдать агрегат вместе с `PlannerTurn`.
- [x] 2.2 Копить usage судьи из pydantic-ai `result.usage()`; отдать агрегат вместе с `JudgeTurn`.
- [x] 2.3 Прокинуть usage попытки/прогона в `RunReport`; печатать в консоли и JSON (`planner` / `judge`).
- [x] 2.4 Тесты: mock HTTP/vLLM usage у planner; mock usage у judge; JSON и краткий итог содержат роли и модели; токенов стенда нет.

## 3. Inspect: default Codex и токены

- [x] 3.1 Default `--analyzer` = `harness`; нет Codex — код 1 и подсказка `--analyzer llm|heuristic`.
- [x] 3.2 `codex exec --json`: профиль из last-message, токены из `turn.completed`; консоль inspect печатает usage.
- [x] 3.3 `inspect --analyzer llm` пишет роль `inspect` тем же OpenAI-парсером.
- [x] 3.4 Тесты: default без флага выбирает harness; нет Codex → 1 и подсказка; mock JSONL + last-message; llm usage не помечен как planner.

## 4. Langfuse

- [x] 4.1 Передать `usage_details` и модель на generation `planner`; добавить generation `judge` с теми же полями; стенд не получает наши токены.
- [x] 4.2 Тесты на mock Langfuse: `update` planner/judge содержит input/output; stand без этого usage.

## 5. Документация и проверка

- [x] 5.1 Обновить README / help: default inspect — Codex; usage в отчёте; OpenRouter и vLLM.
- [x] 5.2 Прогнать pytest, ruff, ty и `openspec validate --change token-usage-logging --strict`.

## 6. Скрипт суммы токенов

- [x] 6.1 `script/sum_attack_usage.py`: сумма in/out из JSON-отчётов атаки по роли и модели, плюс итог; корневой `usage` не дублировать с `runs`.
- [x] 6.2 Тесты: один отчёт, два файла, нет файла → 2; обновить README.
