## Why

Цель, триггер и regex зашиты в Python под один кейс YDEX. Новый сценарий нельзя добавить без правки кода. Нужен каталог атак в YAML, который можно править отдельно.

## What Changes

- Описать атаку в YAML: цель, примеры, триггер, regex, проверка finalize, лимит inject.
- Два готовых файла: `memory-poisoning` и `cross-user-portfolio` (`flow: probe`).
- `--scenario` выбирает имя файла или путь к YAML; `--attacks-dir` задаёт каталог.
- Планировщик берёт цель из YAML, без YDEX в коде.
- `flow: probe` — успех по ответу атакующего, без finalize и жертвы.

Не входит в этот change:

- новые графы под MCP и инструменты;
- LLM-as-a-judge;
- каталог из десятка атак.

## Capabilities

### New Capabilities

- `attack-catalog`: атаки загружаются из YAML, список имён доступен в ошибке CLI.

### Modified Capabilities

- `attack-cli`: `--scenario` больше не ограничен одним именем.
- `memory-poisoning`: текущий кейс живёт в YAML, контракт HTTP тот же.
- `adaptive-planner`: цель и примеры приходят из сценария, не из константы YDEX.

## Impact

Появляется зависимость `pyyaml`. Меняются CLI, конфиг, граф, планировщик и тесты. Каталог — `attacks/` в корне репозитория.

```mermaid
flowchart LR
    yaml[attacks/*.yaml] --> loader
    loader --> graph[LangGraph]
    yaml --> planner[Планировщик]
```
