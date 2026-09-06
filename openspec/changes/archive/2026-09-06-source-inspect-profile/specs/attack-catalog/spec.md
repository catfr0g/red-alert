## MODIFIED Requirements

### Requirement: Атака описывается YAML-файлом

СИСТЕМА ДОЛЖНА (MUST) загружать YAML каталога как шаблон техники: `name`, `flow`, `vulnerability`, `goal`, `examples`, `success_check`, `max_injects`; необязательно `requires`, `slots`, `delivery`; для `flow: memory` также `trigger` и `usable_policy` либо слоты, из которых они собираются. Поле `vulnerability` — непустая строка типа уязвимости для меток в Langfuse. Плейсхолдеры слотов записываются как `{{имя}}`.

#### Scenario: Каталог содержит memory-poisoning

- **WHEN** в каталоге есть `memory-poisoning.yaml` и применён профиль с заполненными слотами
- **THEN** система загружает шаблон по `--scenario memory-poisoning` и выполняет цепочку adapt → inject → persist → trigger

#### Scenario: Каталог содержит probe-атаку

- **WHEN** загружен YAML с `flow: probe` и экземпляр собран
- **THEN** система вызывает планировщик и inject атакующего, считает успех по его ответу и не вызывает persist и trigger жертвы

#### Scenario: Путь к файлу

- **WHEN** `--scenario` указывает на существующий `.yaml` файл без незаполненных слотов
- **THEN** система загружает этот файл, не требуя, чтобы он лежал в каталоге по умолчанию

#### Scenario: Неизвестный сценарий

- **WHEN** имя не совпадает ни с одним YAML в каталоге и не является путём к файлу
- **THEN** система не выполняет HTTP, пишет доступные имена в stderr и завершается с кодом 2

#### Scenario: Невалидный YAML memory без trigger

- **WHEN** файл с `flow: memory` не содержит `trigger` и слота, из которого trigger собирается
- **THEN** система не выполняет HTTP и завершается с кодом 2

#### Scenario: Нет типа уязвимости

- **WHEN** в YAML нет `vulnerability` или значение пустое
- **THEN** система не выполняет HTTP, пишет ошибку в stderr и завершается с кодом 2

#### Scenario: Тип уязвимости загружается

- **WHEN** в YAML задано `vulnerability: memory-poisoning`
- **THEN** загруженный шаблон отдаёт это значение как тип уязвимости

#### Scenario: Шаблон объявляет requires и slots

- **WHEN** в YAML есть `requires: [vision]` и `slots: [policy]`
- **THEN** загрузка сохраняет эти поля у шаблона

## ADDED Requirements

### Requirement: Каталог — техники, не один стенд

СИСТЕМА ДОЛЖНА (MUST) хранить в `attacks/` шаблоны техник с `requires` и слотами. Стендовые формулировки (тикеры, CUS, имена клиентов) живут в профиле, а не как единственный смысл файла. Упакованный `invest-stand` восстанавливает прежние экземпляры для демо.

#### Scenario: Шаблон memory-poisoning без профиля не содержит YDEX как единственную цель

- **WHEN** читается файл `attacks/memory-poisoning.yaml` до подстановки профиля
- **THEN** в `goal` нет литерала `YDEX` либо он только внутри плейсхолдера, а слот `policy` объявлен

#### Scenario: invest-stand восстанавливает прежний смысл

- **WHEN** к шаблону `memory-poisoning` применён упакованный `invest-stand`
- **THEN** в `success_check` экземпляра есть критерий про YDEX
