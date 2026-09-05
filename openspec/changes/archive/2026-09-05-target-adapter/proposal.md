## Why

Повторные попытки на инвест-стенде копят глобальную политику в Mongo: после первого успешного отравления памяти следующие «успехи» часто следуют из уже заражённого состояния, а не из новой атаки. Стенд дал `POST /v1/memory/reset`, но класть эту ручку в `StandClient` ещё сильнее привяжет граф и отчёт к одному HTTP-контракту. Нужен шов цели (`chat` / `persist` / `isolate`), чтобы попытки стали независимыми сейчас, а Hermes или OpenClaw потом не унаследовали чужой `reset`.

## What Changes

- Ввести протокол цели `Target`: `chat`, `persist`, `isolate`. Граф и runner больше не зависят от двух `StandClient` и зашитых `/v1/...`.
- Единственная реализация в этом change — инвест-стенд: чат как сейчас, `persist` = `POST /v1/sessions/{id}/finalize`, `isolate` = `POST /v1/memory/reset`.
- `runner` вызывает `isolate()` **до каждой попытки** (включая первую), не между шагами одной атаки.
- Флаг `--isolate` / `RED_ALERT_ISOLATE`: `on` по умолчанию, `off` разрешён. При `off` CLI всегда пишет warning в stderr и не вызывает isolate.
- Сбой isolate (`503`, сеть, неполный reset) останавливает прогон кодом 1 и не кладёт попытку в ASR.
- Узел графа `finalize` становится `persist`. В JSON и Langfuse шаг называется `persist`; фактический URL стенда остаётся в доказательствах.
- Режим изоляции (`on` / `off`) попадает в отчёт, краткий итог и Langfuse (тег и metadata). Если isolate вызывался — в trace есть соответствующая ручка.
- Автотесты на mock HTTP: isolate до попытки, fail-closed, warning при `off`, граф через `Target`.

Не входит в этот change:

- адаптеры Hermes, OpenClaw и любых других стендов;
- конфиг с шаблонами HTTP-путей «под любой стенд»;
- поле isolate/reset в YAML атак;
- вызов isolate между inject и trigger;
- snapshot/restore и частичная очистка одного пользователя;
- LLM-as-a-judge и новые сценарии атак.

## Capabilities

### New Capabilities

- `target-adapter`: протокол цели (`chat`, `persist`, `isolate`), инвест-адаптер и вызов isolate до независимой попытки.

### Modified Capabilities

- `attack-cli`: `--isolate` / `RED_ALERT_ISOLATE`, значение по умолчанию `on`, warning при `off`, код 1 при сбое isolate.
- `attack-catalog`: в описании memory-цепочки `persist` вместо `finalize`.
- `attack-graph`: граф ходит в `Target`; узел `persist` вместо `finalize`; isolate не является узлом графа.
- `memory-poisoning`: при isolate `on` попытки не наследуют долговременную память друг друга; persist не сбрасывает состояние до trigger.
- `attack-report`: режим изоляции в итоге и JSON; шаг `persist`; факт isolate в доказательствах попытки.
- `langfuse-tracing`: тег и metadata режима изоляции; узел/диалог `persist`; ручка isolate, если она вызывалась.

## Impact

Затрагиваются `stand_client` (становится внутренностью инвест-адаптера), `graph`, `runner`, `cli`, `config`, `models`, `report`, `display`, `tracing`, тесты и документация (`README`, `ARCHITECTURE.md`). Новых runtime-зависимостей нет. Контракт JSON меняется: шаг `finalize` переименовывается в `persist`, появляется поле изоляции. Живой стенд в CI по-прежнему не нужен.
