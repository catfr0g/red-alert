## 1. Каталог и загрузчик

- [x] 1.1 Добавить `pyyaml` и модуль загрузки YAML в Pydantic-модель.
- [x] 1.2 Положить `attacks/memory-poisoning.yaml` и `attacks/cross-user-portfolio.yaml`.

## 2. Прогон

- [x] 2.1 Подключить загрузчик к CLI и конфигу: имя, путь, `--attacks-dir`.
- [x] 2.2 Граф: `memory` как сейчас; `probe` — успех по ответу атакующего без finalize/trigger.
- [x] 2.3 Убрать YDEX из системного промпта планировщика.

## 3. Тесты и документы

- [x] 3.1 Покрыть загрузку, битый YAML, probe и выбор файла по пути.
- [x] 3.2 Обновить README, ARCHITECTURE.md и docs/product.md.
- [x] 3.3 Прогнать pytest, ruff и OpenSpec-валидацию change.
