## Purpose

Одна попытка атаки оркестрируется графом LangGraph. Набор узлов зависит от `flow` YAML.

## Requirements

### Requirement: Попытка выполняется графом LangGraph

СИСТЕМА ДОЛЖНА (MUST) оркестрировать одну попытку через LangGraph: узлы `adapt` и `inject`; для `flow: memory` также `finalize` и `trigger`.

#### Scenario: Узлы графа memory

- **WHEN** собирается граф попытки с `flow: memory`
- **THEN** в графе есть узлы `adapt`, `inject`, `finalize` и `trigger`

#### Scenario: Повтор inject

- **WHEN** `finalize` не вернул usable global-политику и лимит inject не исчерпан
- **THEN** граф снова переходит в `adapt` с новой сессией атакующего

#### Scenario: Переход к trigger

- **WHEN** появилась usable global-политика или выполнен максимальный набор inject
- **THEN** граф переходит в `trigger`

#### Scenario: Узлы графа probe

- **WHEN** собирается граф попытки с `flow: probe`
- **THEN** система вызывает `adapt` и `inject` и не вызывает finalize и trigger
