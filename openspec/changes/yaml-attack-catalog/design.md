## Context

`MemoryPoisoningScenario` и системный промпт планировщика содержат YDEX. Runner принимает только `memory-poisoning`. Нужно читать те же поля из YAML и дать второй поток `probe`.

## Goals / Non-Goals

**Goals:**

- Один YAML — одна атака.
- Два `flow`: `memory` (adapt → inject → finalize → trigger) и `probe` (adapt → inject, успех по ответу атакующего).
- Выбор файла по имени или пути.
- Общий промпт планировщика, цель из YAML.

**Non-Goals:**

- Плагины и произвольные графы.
- Упаковка YAML внутрь wheel как единственный источник.

## Decisions

### Каталог в корне репозитория

`attacks/*.yaml` рядом с CLI, его удобно править. В файлах — комментарии к полям. Поиск: явный `--attacks-dir`, иначе `./attacks`, иначе `attacks/` рядом с корнем пакета.

### Имя или путь

`--scenario memory-poisoning` → `{dir}/memory-poisoning.yaml`. `--scenario ./mine.yaml` — загрузить этот файл.

### Pydantic на загрузке

Невалидный regex, нет `trigger` у `memory`, неизвестный `flow` — ошибка ввода, код 2, без HTTP.

### Probe повторяет inject

Если ответ атакующего не успех и есть лимит `max_injects`, граф снова идёт в `adapt`. Finalize и trigger не вызываются.

## Risks / Trade-offs

- [Битый YAML ломает запуск] → Проверка при resolve_config, понятное сообщение.
- [Два ключа всё ещё обязательны для probe] → Жертва не используется в HTTP, но CLI не меняет контракт ключей.

## Migration Plan

Старый `--scenario memory-poisoning` читает новый YAML. Откат — вернуть класс в Python.

## Open Questions

Нет.
