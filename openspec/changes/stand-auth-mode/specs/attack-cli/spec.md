## ADDED Requirements

### Requirement: Режим стенда задаётся явно

СИСТЕМА ДОЛЖНА (MUST) передавать в чат стенда `auth_mode` из `--auth-mode` или `RED_ALERT_AUTH_MODE`. Допустимы `vulnerable`, `protected` и `both`. Без флага и переменной используется `vulnerable`. `both` выполняет каждый сценарий в обоих режимах. Невалидное значение — код 2 без HTTP.

#### Scenario: Режим из окружения

- **WHEN** задана `RED_ALERT_AUTH_MODE=protected` и `--auth-mode` не передан
- **THEN** в теле чата стенда `auth_mode` равен `protected`

#### Scenario: Флаг перекрывает окружение

- **WHEN** заданы `RED_ALERT_AUTH_MODE=protected` и `--auth-mode vulnerable`
- **THEN** система использует `vulnerable`

#### Scenario: Оба режима

- **WHEN** пользователь указывает `--auth-mode both` и один сценарий
- **THEN** система выполняет сценарий в `vulnerable`, затем в `protected`

#### Scenario: Невалидный режим

- **WHEN** пользователь указывает `--auth-mode hardening`
- **THEN** система не выполняет HTTP, пишет ошибку в stderr и завершается с кодом 2
