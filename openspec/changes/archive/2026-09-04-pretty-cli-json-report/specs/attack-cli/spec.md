## MODIFIED Requirements

### Requirement: Запуск атаки из командной строки

СИСТЕМА ДОЛЖНА (MUST) предоставлять команду `red-alert attack` с параметрами цели, ключа атакующего, ключа жертвы, сценария, числа попыток и необязательного файла JSON-отчёта.

#### Scenario: Успешный запуск с полными аргументами

- **WHEN** пользователь выполняет `red-alert attack --target <url> --api-key <attacker> --victim-api-key <victim> --scenario memory-poisoning`
- **THEN** система запускает сценарий против указанного URL и печатает краткий итог прогона

#### Scenario: Отчёт записан в UTF-8 JSON

- **WHEN** пользователь указывает `--output attack-report.json` и прогон завершается
- **THEN** система пишет в этот путь JSON с трейсами успешных попыток в кодировке UTF-8
