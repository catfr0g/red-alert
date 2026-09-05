## ADDED Requirements

### Requirement: Режим стенда в отчёте

СИСТЕМА ДОЛЖНА (MUST) печатать `auth_mode` в кратком итоге каждого прогона и класть его в JSON. Если в одном запуске есть и `vulnerable`, и `protected`, система ДОЛЖНА (MUST) напечатать ASR отдельно по каждому режиму.

#### Scenario: JSON содержит auth_mode

- **WHEN** прогон одного сценария в `protected` завершается
- **THEN** JSON содержит `"auth_mode": "protected"`

#### Scenario: Сравнение двух режимов

- **WHEN** задан `--auth-mode both`
- **THEN** в консоли есть ASR для `vulnerable` и для `protected`
