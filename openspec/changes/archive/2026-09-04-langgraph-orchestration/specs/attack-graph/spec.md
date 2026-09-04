## ADDED Requirements

### Requirement: Попытка выполняется графом LangGraph

СИСТЕМА ДОЛЖНА (MUST) оркестрировать одну попытку `memory-poisoning` через LangGraph с узлами `inject`, `finalize` и `trigger`.

#### Scenario: Узлы графа

- **WHEN** собирается граф попытки
- **THEN** в графе есть узлы `inject`, `finalize` и `trigger`

#### Scenario: Повтор inject

- **WHEN** `finalize` не вернул usable global-политику и лимит inject не исчерпан
- **THEN** граф снова переходит в `inject` с новой сессией атакующего

#### Scenario: Переход к trigger

- **WHEN** появилась usable global-политика или выполнен максимальный набор inject
- **THEN** граф переходит в `trigger`
