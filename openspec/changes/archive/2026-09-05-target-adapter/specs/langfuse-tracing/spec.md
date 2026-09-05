## ADDED Requirements

### Requirement: Режим изоляции попадает в Langfuse

СИСТЕМА ДОЛЖНА (MUST) при включённом экспорте помечать каждую попытку тегом `isolation:on` или `isolation:off` и тем же значением в metadata `isolation`. Если изоляция включена и isolate выполнился, в том же trace есть span isolate и тег `endpoint:/v1/memory/reset`.

#### Scenario: Тег isolation on

- **WHEN** экспорт включён и прогон идёт с изоляцией по умолчанию
- **THEN** у trace попытки есть тег `isolation:on` и metadata `isolation` со значением `on`

#### Scenario: Тег isolation off

- **WHEN** экспорт включён и задано `--isolate off`
- **THEN** у trace попытки есть тег `isolation:off` и нет `endpoint:/v1/memory/reset`

#### Scenario: Isolate виден как span

- **WHEN** экспорт включён, изоляция включена и isolate завершился успешно
- **THEN** в trace попытки есть span isolate до узлов графа и тег `endpoint:/v1/memory/reset`

#### Scenario: Вторая попытка той же уязвимости — полный trace

- **WHEN** экспорт включён, изоляция включена и идут две попытки одного сценария
- **THEN** у каждой попытки свой trace, и в каждом есть span isolate до узлов графа

## MODIFIED Requirements

### Requirement: Trace показывает диалоги, не внутренний state

СИСТЕМА ДОЛЖНА (MUST) писать в Langfuse ход как чат двух агентов: планировщик и стенд. Input/output — сообщения `{role, content}` или краткий итог узла. В наблюдения не входят `AttemptState`, список `steps` и reasoning планировщика.

#### Scenario: Ход атакующего читается как чат

- **WHEN** экспорт включён и прошла попытка `flow: memory`
- **THEN** есть диалог `attacker` с сообщениями user/assistant и `persist.facts`, затем отдельный диалог `victim`

#### Scenario: Узел графа не содержит AttemptState

- **WHEN** CallbackHandler пишет input узла `inject`
- **THEN** там список messages, а не строка `AttemptState(...)` и не тела всех предыдущих шагов

#### Scenario: Probe — один диалог

- **WHEN** попытка с `flow: probe`
- **THEN** есть диалог `attacker` и нет диалога `victim`

#### Scenario: Развилки графа не попадают в Langfuse

- **WHEN** LangGraph считает `after_adapt` / `after_inject` / `after_persist`
- **THEN** для этих шагов в Langfuse нет отдельных span

### Requirement: Метки ручки и типа уязвимости

СИСТЕМА ДОЛЖНА (MUST) помечать trace попытки тегом `vulnerability:<тип>` из YAML и тегами `endpoint:<путь>` для каждой уникальной ручки стенда в шагах попытки. Путь нормализуется: `/v1/chat/completions`, `/v1/sessions/finalize` и `/v1/memory/reset` без идентификатора сессии. Шаг планировщика в теги `endpoint:*` не входит.

#### Scenario: Memory-атака помечает чат и finalize

- **WHEN** успешна попытка с `flow: memory` и шагами payload, persist и trigger
- **THEN** у trace есть теги `vulnerability:` из YAML, `endpoint:/v1/chat/completions` и `endpoint:/v1/sessions/finalize`

#### Scenario: Probe не помечает finalize

- **WHEN** попытка с `flow: probe` ходила только в чат стенда
- **THEN** у trace есть `endpoint:/v1/chat/completions` и нет `endpoint:/v1/sessions/finalize`

#### Scenario: Планировщик не считается ручкой стенда

- **WHEN** в попытке есть шаг `adapt`
- **THEN** теги `endpoint:*` не содержат URL планировщика
