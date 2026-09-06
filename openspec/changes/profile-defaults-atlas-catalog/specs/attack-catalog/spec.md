## MODIFIED Requirements

### Requirement: Имя атаки включает код MITRE ATLAS

СИСТЕМА ДОЛЖНА (MUST) использовать в каталоге формат `{AML.Txxxx}_{slug}` для поля `name` и имени файла `{name}.yaml`. Ключ binding в StandProfile совпадает с `name`. `--scenario` принимает это имя или путь к файлу.

#### Scenario: Загрузка по ATLAS-имени

- **WHEN** в каталоге есть `AML.T0080.000_memory-poisoning.yaml` и профиль с заполненными слотами
- **THEN** `--scenario AML.T0080.000_memory-poisoning` загружает шаблон и собирает экземпляр

#### Scenario: Список доступных имён

- **WHEN** пользователь указывает неизвестный `--scenario`
- **THEN** stderr содержит ATLAS-имена из каталога

### Requirement: Каталог покрывает OWASP Agentic / ATLAS

СИСТЕМА ДОЛЖНА (MUST) хранить шаблоны техник с `requires`, слотами и полем `vulnerability`; не менее 18 файлов, сгруппированных по основной технике ATLAS (prompt injection, tool misuse, identity abuse, memory poisoning, recon, trust exploit и др.).

#### Scenario: Каталог отсортирован по name

- **WHEN** загружается весь каталог без `--scenario`
- **THEN** порядок прогона — алфавитный по ATLAS-имени
