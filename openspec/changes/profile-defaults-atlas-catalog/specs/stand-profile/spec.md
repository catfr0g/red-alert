## ADDED Requirements

### Requirement: defaults снижают дублирование bindings

СИСТЕМА ДОЛЖНА (MUST) поддерживать опциональный top-level `defaults` с `target`, `eval`, `persist`. При сборке runtime binding накладывается поверх `defaults`: скаляры перекрывают, словари (`custom_body`, `custom_headers`, `expected_body`) мержатся. `eval.inherit: target` — eval как target binding; `inherit: defaults` или `null` — из `defaults.eval`. `persist: {}` берёт `defaults.persist`; `persist: null` — без persist.

#### Scenario: Общий endpoint в defaults

- **WHEN** в профиле `defaults.target.endpoint` задан, а в binding только `policy`/`trigger`/`proof`
- **THEN** runtime binding использует endpoint из defaults

#### Scenario: eval наследует target клиента

- **WHEN** в binding `eval.inherit: target`
- **THEN** eval получает endpoint и bearer target с overlay полей eval

### Requirement: applicable помечает неприменимую технику

СИСТЕМА ДОЛЖНА (MUST) пропускать binding с `applicable: false` при сборке каталога: сценарий не запускается, в skipped — имя и причина. Отсутствие поля трактуется как применимо.

#### Scenario: Analyzer пометил технику неприменимой

- **WHEN** в профиле `AML.T0080.000_memory-poisoning.applicable: false`
- **THEN** `attack` без `--scenario` не запускает эту технику и перечисляет её в skipped
