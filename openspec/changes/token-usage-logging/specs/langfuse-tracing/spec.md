## ADDED Requirements

### Requirement: Generation планировщика и судьи получают usage

СИСТЕМА ДОЛЖНА (MUST) при включённом экспорте в Langfuse передавать на generation `planner` и `judge` модель и `usage_details` с входными и выходными токенами того вызова. Generation стенда usage Red Alert не получает. Если экспорт выключен, usage остаётся только в консоли и JSON.

#### Scenario: Planner generation содержит токены

- **WHEN** экспорт включён и планировщик вернул usage
- **THEN** observation `planner` обновляется с моделью планировщика и `usage_details.input` / `usage_details.output`

#### Scenario: Judge generation содержит токены

- **WHEN** экспорт включён и судья вернул usage
- **THEN** в trace попытки есть generation `judge` с моделью судьи и `usage_details.input` / `usage_details.output`

#### Scenario: Стенд без наших токенов

- **WHEN** экспорт включён и стенд ответил на payload
- **THEN** observation стенда не получает usage планировщика или судьи
