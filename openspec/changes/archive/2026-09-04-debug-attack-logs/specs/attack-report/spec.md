## ADDED Requirements

### Requirement: JSON-трейсы неуспешных попыток в debug

СИСТЕМА ДОЛЖНА (MUST) в режиме debug включать в JSON `traces` все попытки, в том числе неуспешные, с полной цепочкой шагов.

#### Scenario: Неуспешная попытка попадает в traces

- **WHEN** включён debug и попытка завершилась без успеха
- **THEN** в JSON `traces` есть эта попытка и её шаги

#### Scenario: Без debug неуспешная попытка не в traces

- **WHEN** debug выключен и попытка неуспешна
- **THEN** её шаги отсутствуют в JSON `traces`
