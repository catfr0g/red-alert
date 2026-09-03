## ADDED Requirements

### Requirement: Шаг adapt в доказательствах успешной попытки

СИСТЕМА ДОЛЖНА (MUST) включать в JSON-трейс успешной попытки шаг `adapt` с актором `planner` до шага payload: URL планировщика, тело запроса без заголовка авторизации и тело ответа.

#### Scenario: Успешная попытка начинается с adapt

- **WHEN** попытка успешна и пишется JSON `traces`
- **THEN** первый шаг трейса — `adapt`, за ним payload, finalize и trigger

#### Scenario: Секрет планировщика скрыт в трейсе

- **WHEN** отчёт содержит шаг `adapt`
- **THEN** в JSON нет значения `OPENAI_API_KEY` и нет заголовка `Authorization`
