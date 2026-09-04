## ADDED Requirements

### Requirement: Атака описывается YAML-файлом

СИСТЕМА ДОЛЖНА (MUST) загружать сценарий атаки из YAML: `name`, `flow`, `goal`, `examples`, `success_pattern`, `max_injects`; для `flow: memory` также `trigger` и `usable_policy`.

#### Scenario: Каталог содержит memory-poisoning

- **WHEN** в каталоге есть `memory-poisoning.yaml`
- **THEN** система загружает его по `--scenario memory-poisoning` и выполняет цепочку adapt → inject → finalize → trigger

#### Scenario: Каталог содержит probe-атаку

- **WHEN** загружен YAML с `flow: probe`
- **THEN** система вызывает планировщик и inject атакующего, считает успех по его ответу и не вызывает finalize и trigger жертвы

#### Scenario: Путь к файлу

- **WHEN** `--scenario` указывает на существующий `.yaml` файл
- **THEN** система загружает этот файл, не требуя, чтобы он лежал в каталоге по умолчанию

#### Scenario: Неизвестный сценарий

- **WHEN** имя не совпадает ни с одним YAML в каталоге и не является путём к файлу
- **THEN** система не выполняет HTTP, пишет доступные имена в stderr и завершается с кодом 2

#### Scenario: Невалидный YAML memory без trigger

- **WHEN** файл с `flow: memory` не содержит `trigger`
- **THEN** система не выполняет HTTP и завершается с кодом 2
