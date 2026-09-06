## ADDED Requirements

### Requirement: Usage прогона в итоге и JSON

СИСТЕМА ДОЛЖНА (MUST) печатать в кратком итоге атаки и класть в JSON-отчёт блок `usage` с ролями `planner` и `judge`: имя модели, `input_tokens`, `output_tokens`. Если в прогоне несколько сценариев, суммарный JSON содержит суммарный `usage` и тот же блок в каждом элементе `runs`.

#### Scenario: JSON одного сценария содержит usage

- **WHEN** прогон одного сценария завершается и задан `--output`
- **THEN** JSON содержит `usage.planner` и `usage.judge` с полями модели, input и output

#### Scenario: Итог в консоли показывает токены ролей

- **WHEN** прогон завершается успешно
- **THEN** краткий итог содержит строки planner и judge с моделью и числами input/output

#### Scenario: Несколько сценариев суммируют usage

- **WHEN** прогон без `--scenario` пишет JSON нескольких run
- **THEN** корневой объект содержит суммарный `usage` по ролям, и каждый элемент `runs` содержит свой `usage`
