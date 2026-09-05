## Purpose

Опциональная запись всех попыток атаки в локальный Langfuse: живые диалоги графа, метки исхода, ручки и типа уязвимости.

## Requirements

### Requirement: Все попытки уходят в Langfuse

СИСТЕМА ДОЛЖНА (MUST) при включённом экспорте записывать в Langfuse каждую попытку: успешную и неуспешную. Одна попытка — один trace. Узлы графа уходят во время выполнения через `langfuse.langchain.CallbackHandler`. JSON-отчёт от этого не меняется.

#### Scenario: Успешная попытка записана

- **WHEN** экспорт включён и попытка признана успешной
- **THEN** в Langfuse есть trace этой попытки с тегом `outcome:success`

#### Scenario: Неуспешная попытка тоже записана

- **WHEN** экспорт включён и попытка завершилась без успеха
- **THEN** в Langfuse есть trace этой попытки с тегом `outcome:failure`

#### Scenario: Экспорт выключен

- **WHEN** `RED_ALERT_LANGFUSE` не задана
- **THEN** система не обращается к Langfuse и завершает прогон как обычно

### Requirement: Граф пишется в реальном времени

СИСТЕМА ДОЛЖНА (MUST) при включённом экспорте передавать в запуск LangGraph официальный `langfuse.langchain.CallbackHandler` и сбрасывать spans после каждого узла, чтобы граф появлялся в Langfuse по мере выполнения, а не одним пакетом после попытки.

#### Scenario: CallbackHandler на графе попытки

- **WHEN** экспорт включён и выполняется попытка
- **THEN** в конфигурации `stream`/`invoke` графа есть CallbackHandler Langfuse

#### Scenario: Узел уходит до конца попытки

- **WHEN** экспорт включён и узел графа завершился
- **THEN** система делает flush в Langfuse до перехода к следующему узлу

### Requirement: Trace показывает диалоги, не внутренний state

СИСТЕМА ДОЛЖНА (MUST) писать в Langfuse ход как чат двух агентов: планировщик и стенд. Input/output — сообщения `{role, content}` или краткий итог узла. В наблюдения не входят `AttemptState`, список `steps` и reasoning планировщика.

#### Scenario: Ход атакующего читается как чат

- **WHEN** экспорт включён и прошла попытка `flow: memory`
- **THEN** есть диалог `attacker` с сообщениями user/assistant и `finalize.facts`, затем отдельный диалог `victim`

#### Scenario: Узел графа не содержит AttemptState

- **WHEN** CallbackHandler пишет input узла `inject`
- **THEN** там список messages, а не строка `AttemptState(...)` и не тела всех предыдущих шагов

#### Scenario: Probe — один диалог

- **WHEN** попытка с `flow: probe`
- **THEN** есть диалог `attacker` и нет диалога `victim`

#### Scenario: Развилки графа не попадают в Langfuse

- **WHEN** LangGraph считает `after_adapt` / `after_inject` / `after_finalize`
- **THEN** для этих шагов в Langfuse нет отдельных span

### Requirement: Метки ручки и типа уязвимости

СИСТЕМА ДОЛЖНА (MUST) помечать trace попытки тегом `vulnerability:<тип>` из YAML и тегами `endpoint:<путь>` для каждой уникальной ручки стенда в шагах попытки. Путь нормализуется: `/v1/chat/completions` и `/v1/sessions/finalize` без идентификатора сессии. Шаг планировщика в теги `endpoint:*` не входит.

#### Scenario: Memory-атака помечает чат и finalize

- **WHEN** успешна попытка с `flow: memory` и шагами payload, finalize и trigger
- **THEN** у trace есть теги `vulnerability:` из YAML, `endpoint:/v1/chat/completions` и `endpoint:/v1/sessions/finalize`

#### Scenario: Probe не помечает finalize

- **WHEN** попытка с `flow: probe` ходила только в чат стенда
- **THEN** у trace есть `endpoint:/v1/chat/completions` и нет `endpoint:/v1/sessions/finalize`

#### Scenario: Планировщик не считается ручкой стенда

- **WHEN** в попытке есть шаг `adapt`
- **THEN** теги `endpoint:*` не содержат URL планировщика

### Requirement: Оценка успеха попытки

СИСТЕМА ДОЛЖНА (MUST) ставить на trace попытки score `attack_success` со значением true при успехе и false при неуспехе.

#### Scenario: Score у успеха

- **WHEN** попытка успешна и экспорт включён
- **THEN** у trace score `attack_success` истинный

#### Scenario: Score у провала

- **WHEN** попытка неуспешна и экспорт включён
- **THEN** у trace score `attack_success` ложный

### Requirement: Секреты не попадают в Langfuse

СИСТЕМА ДОЛЖНА (MUST) не записывать в Langfuse значения ключей стенда, планировщика и Langfuse в открытом виде.

#### Scenario: Ключи замаскированы в span

- **WHEN** в шаге попытки есть `OPENAI_API_KEY` или ключ стенда
- **THEN** в данных, отправленных в Langfuse, этих значений нет

### Requirement: Локальный Langfuse через docker-compose

СИСТЕМА ДОЛЖНА (MUST) поставлять в репозитории `docker-compose.yml`, который поднимает Langfuse локально. После успешного запуска UI доступен на `http://localhost:3000`.

#### Scenario: Compose поднимает UI

- **WHEN** пользователь выполняет `docker compose up` из корня репозитория и дожидается готовности
- **THEN** HTTP-ответ с `http://localhost:3000` не является отказом соединения
