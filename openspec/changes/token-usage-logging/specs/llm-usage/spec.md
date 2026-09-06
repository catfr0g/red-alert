## ADDED Requirements

### Requirement: Токены привязаны к роли и модели

СИСТЕМА ДОЛЖНА (MUST) для каждого вызова своей LLM записывать входные токены, выходные токены, роль (`inspect`, `planner` или `judge`) и фактическое имя модели. Стоимость в валюте не считается. Токены целевого стенда не записываются.

#### Scenario: Планировщик и судья — разные модели

- **WHEN** прогон атаки вызвал планировщик с моделью A и судью с моделью B
- **THEN** в usage есть отдельная запись роли `planner` с моделью A и роли `judge` с моделью B, у каждой свои input и output

#### Scenario: Inspect не смешивается с планировщиком

- **WHEN** `inspect --analyzer llm` использует ту же модель, что и планировщик атаки
- **THEN** токены inspect помечены ролью `inspect`, а не `planner`

#### Scenario: Стоимость и стенд отсутствуют

- **WHEN** провайдер вернул `usage.cost` или стенд вернул свой `usage`
- **THEN** в отчёте Red Alert нет поля стоимости и нет токенов стенда

### Requirement: OpenAI-совместимый usage без привязки к OpenRouter

СИСТЕМА ДОЛЖНА (MUST) читать только стандартные поля `usage.prompt_tokens` и `usage.completion_tokens` (или эквивалент pydantic-ai / Codex). Поведение одинаково для OpenRouter и для своего vLLM. Если `usage` нет, роль и модель всё равно записываются, токены этой записи равны 0.

#### Scenario: vLLM без cost

- **WHEN** ответ chat completions содержит `usage.prompt_tokens` и `usage.completion_tokens` и не содержит `cost`
- **THEN** система записывает эти input и output токены

#### Scenario: Нет поля usage

- **WHEN** успешный ответ LLM не содержит `usage`
- **THEN** в записи роли есть модель, `input_tokens` = 0 и `output_tokens` = 0

#### Scenario: Ретраи суммируются

- **WHEN** планировщик сделал два HTTP-вызова в одном `plan` и оба вернули usage
- **THEN** в роли `planner` input и output равны сумме обоих вызовов

### Requirement: Inspect по умолчанию использует Codex

СИСТЕМА ДОЛЖНА (MUST) без `--analyzer` выбирать backend `harness`. `--analyzer llm` и `--analyzer heuristic` остаются доступны. Если Codex CLI отсутствует, система НЕ ДОЛЖНА (MUST NOT) молча переключаться на другой backend: код 1, профиль не пишется, в stderr есть подсказка указать `--analyzer llm` или `--analyzer heuristic`.

#### Scenario: Default без флага — harness

- **WHEN** пользователь выполняет `red-alert inspect <каталог>` без `--analyzer`
- **THEN** система вызывает Codex harness, а не llm и не heuristic

#### Scenario: Нет Codex на default inspect

- **WHEN** команда `codex` не найдена и `--analyzer` не задан
- **THEN** процесс завершается с кодом 1, профиль не создан, stderr содержит `--analyzer llm` и `--analyzer heuristic`

#### Scenario: Явный llm без ключа

- **WHEN** задан `--analyzer llm` и нет `OPENAI_API_KEY`
- **THEN** система завершается с кодом 2 и не вызывает Codex

### Requirement: Inspect через Codex пишет токены из JSONL

СИСТЕМА ДОЛЖНА (MUST) при `harness` запускать `codex exec` с `--json`, брать профиль из `--output-last-message`, а токены — из событий `turn.completed`. В консоли после пути профиля печатается роль `inspect`, модель и input/output.

#### Scenario: Успешный harness печатает usage

- **WHEN** Codex вернул профиль в last-message и `turn.completed` с `input_tokens` и `output_tokens`
- **THEN** процесс код 0, профиль записан, в консоли есть input и output inspect

#### Scenario: JSONL не подменяет профиль

- **WHEN** stdout Codex — поток JSON-событий, а last-message содержит JSON StandProfile
- **THEN** записанный профиль берётся из last-message, не из первой JSONL-строки

### Requirement: Скрипт суммирует токены отчёта атаки

СИСТЕМА ДОЛЖНА (MUST) предоставлять скрипт `script/sum_attack_usage.py`, который читает один или несколько JSON-отчётов `red-alert attack` и печатает сумму входных и выходных токенов по ролям и моделям, затем общий итог. Если в файле есть корневой `usage`, скрипт не прибавляет ещё раз `runs[].usage`. Нет файла или не JSON — код 2. Стоимость не печатается.

#### Scenario: Один отчёт

- **WHEN** пользователь запускает скрипт на JSON с `usage.planner` in=10 out=2 и `usage.judge` in=4 out=1
- **THEN** процесс код 0, в выводе есть эти числа по ролям и итог in=14 out=3

#### Scenario: Несколько файлов

- **WHEN** скрипт получает два отчёта с токенами планировщика 10 и 5
- **THEN** в итоге planner input равен 15

#### Scenario: Нет файла

- **WHEN** указан путь, которого нет
- **THEN** процесс завершается с кодом 2 и не печатает итог
