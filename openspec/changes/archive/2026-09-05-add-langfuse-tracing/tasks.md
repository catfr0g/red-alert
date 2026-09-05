## 1. Каталог

- [x] 1.1 Добавить обязательное поле `vulnerability` в YAML-модель; обновить `memory-poisoning.yaml` и `cross-user-portfolio.yaml`.

## 2. Приёмник и конфиг

- [x] 2.1 Читать `RED_ALERT_LANGFUSE`, ключи и `LANGFUSE_BASE_URL`; без флага — no-op; без ключей при флаге — код 2.
- [x] 2.2 Протокол приёмника: `ping`, `trace_attempt`, `close`; CallbackHandler на графе; нормализация ручки; теги `outcome`, `vulnerability`, `endpoint:*`; score `attack_success`; маскировка секретов.

## 3. Прогон CLI

- [x] 3.1 До атаки `ping`; во время попытки CallbackHandler + flush узлов; сбой Langfuse — код 1, без JSON-отчёта; зависимости `langfuse` и `langchain`.

## 4. Compose

- [x] 4.1 `docker-compose.yml` локального Langfuse (pin образов, headless init, UI `:3000`); плейсхолдеры секретов только в example.

## 5. Тесты и документы

- [x] 5.1 Тесты: выключено; нет ключа; ping/export ошибка; метки memory и probe; YAML без `vulnerability`.
- [x] 5.2 README, `.env.example`, `docs/product.md`; pytest, ruff, OpenSpec-валидация.

## 6. Живой граф

- [x] 6.1 Переключить приёмник на `langfuse.langchain.CallbackHandler` и `graph.stream` с flush после узла.
- [x] 6.2 Прокинуть callbacks в `run_attempt` / `run_attack`; после попытки дописать теги и `attack_success`.
- [x] 6.3 Тесты живого CallbackHandler; обновить design/spec; pytest, ruff, OpenSpec-валидация.

## 7. Диалоги вместо dump state

- [x] 7.1 Input/output наблюдений — чат агентов; CallbackHandler не пишет AttemptState.
- [x] 7.2 После finalize новый диалог (ретрай или victim); тесты и OpenSpec.
