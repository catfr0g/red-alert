## ADDED Requirements

### Requirement: Профиль стенда задаёт capability и привязки

СИСТЕМА ДОЛЖНА (MUST) загружать StandProfile из YAML: для каждой известной capability поле `status` (`present`, `absent`, `unknown`) и `confidence` (`high`, `low`); для шаблонов атак — `bindings` со значениями слотов. Неизвестный ключ capability или невалидный статус останавливают загрузку с кодом 2. Отсутствующая capability в профиле считается `unknown` с `confidence: low`.

#### Scenario: Упакованный invest-stand загружается

- **WHEN** пользователь передаёт `--profile profiles/invest-stand.yaml` с валидным YAML
- **THEN** система применяет этот файл с заполненными bindings текущих техник каталога

#### Scenario: Явный путь к профилю

- **WHEN** пользователь передаёт `--profile path/to/profile.yaml` с валидным YAML
- **THEN** система применяет этот файл вместо упакованного

#### Scenario: Невалидный статус capability

- **WHEN** в профиле у capability `status: maybe`
- **THEN** система не выполняет HTTP к стенду, пишет ошибку в stderr и завершается с кодом 2

#### Scenario: Нет файла профиля

- **WHEN** `--profile` указывает на отсутствующий файл
- **THEN** система не выполняет HTTP к стенду, пишет ошибку в stderr и завершается с кодом 2

### Requirement: Применение профиля к шаблону

СИСТЕМА ДОЛЖНА (MUST) для каждого шаблона решить: skip из-за capability, skip из-за пустого слота или собрать экземпляр. Skip при `requires` содержит capability со `status: absent` и `confidence: high`. Capability со `status: unknown` не выключает шаблон. Если после подстановки хотя бы один объявленный слот пустой — skip, значения не выдумывать. Иначе подставить bindings в поля шаблона и получить прогоняемый сценарий.

#### Scenario: Нет vision — image-атака отсекается

- **WHEN** шаблон требует `vision`, а в профиле `vision.status=absent` и `confidence=high`
- **THEN** сценарий не запускается, в skipped есть его имя и причина про vision

#### Scenario: Неизвестная память не отсекает

- **WHEN** шаблон требует `persistent_memory`, а в профиле этой capability нет или она `unknown`
- **THEN** система не пропускает шаблон из-за capability и пытается собрать экземпляр по слотам

#### Scenario: Пустой слот — skip

- **WHEN** шаблон объявляет слот `policy`, а в bindings этого имени слота нет или значение пустое
- **THEN** сценарий не запускается, в skipped есть причина про незаполненный слот

#### Scenario: Слоты заполнены — экземпляр готов

- **WHEN** у шаблона `AML.T0080.000_memory-poisoning` в профиле заполнены все слоты
- **THEN** собранный сценарий содержит конкретные `goal`, `trigger` и `success_check` без плейсхолдеров `{{` и проходит те же проверки, что обычный YAML
