## ADDED Requirements

### Requirement: Для атаки нужен LLM планировщика

СИСТЕМА ДОЛЖНА (MUST) читать `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `MODEL` и `MAX_TOKENS` из окружения или `.env`. Без ключа и модели планировщика атака не запускается.

#### Scenario: Ключ планировщика отсутствует

- **WHEN** не задана `OPENAI_API_KEY`, а ключи стенда заданы
- **THEN** система не выполняет HTTP-запросы, пишет ошибку в stderr и завершается с кодом 2

#### Scenario: Модель отсутствует

- **WHEN** не задана `MODEL`, а `OPENAI_API_KEY` задан
- **THEN** система не выполняет HTTP-запросы, пишет ошибку в stderr и завершается с кодом 2

#### Scenario: Базовый URL и лимит по умолчанию

- **WHEN** заданы `OPENAI_API_KEY` и `MODEL`, а `OPENAI_BASE_URL` и `MAX_TOKENS` не заданы
- **THEN** система использует `https://openrouter.ai/api/v1` и `MAX_TOKENS=2048`

#### Scenario: Некорректный MAX_TOKENS

- **WHEN** `MAX_TOKENS` не целое число >= 1
- **THEN** система не выполняет HTTP-запросы, пишет ошибку в stderr и завершается с кодом 2

## MODIFIED Requirements

### Requirement: Ключи не попадают в вывод

СИСТЕМА ДОЛЖНА (MUST) не печатать секреты API-ключей атакующего, жертвы и планировщика в stdout и stderr.

#### Scenario: Отчёт после прогона

- **WHEN** прогон завершается и печатается отчёт
- **THEN** в выводе нет значений ключей стенда и `OPENAI_API_KEY` в открытом виде
