## 1. Протокол цели

- [x] 1.1 Добавить `Target` (`chat`, `persist`, `isolate`) и `IsolateError`; обернуть инвест-стенд в `InvestStandTarget` с principal `attacker`/`victim`.
- [x] 1.2 В инвест-адаптере: `chat` → `/v1/chat/completions`, `persist` → `/v1/sessions/{id}/finalize`, `isolate` → `/v1/memory/reset` ключом атакующего; успех isolate только при HTTP 2xx и `status=reset`.

## 2. Граф попытки

- [x] 2.1 Перевести граф на `Target`: узел `finalize` заменить на `persist`; развилка `after_persist`; isolate в граф не добавлять.
- [x] 2.2 Обновить `dialogue`: persist вместо finalize, скрыть `after_persist`; комментарии YAML каталога — цепочка adapt → inject → persist → trigger.

## 3. Изоляция попыток

- [x] 3.1 В `run_attack` при `isolation=on` вызывать `isolate()` до каждой попытки и класть шаг `isolate` первым в `steps`; при ошибке — `IsolateError`, попытку в ASR не считать.
- [x] 3.2 При `isolation=off` isolate не вызывать; `prior_notes` планировщика между попытками сохранить.

## 4. CLI и конфиг

- [x] 4.1 Добавить `--isolate` / `RED_ALERT_ISOLATE` (`on`/`off`, default `on`, флаг перекрывает env); невалидное значение — код 2.
- [x] 4.2 При `off` один warning в stderr до первого HTTP; при сбое isolate — код 1 и без JSON-отчёта атаки.

## 5. Отчёт и Langfuse

- [x] 5.1 Поле `isolation` в `RunReport`, кратком итоге и JSON; в traces успешной попытки при `on` шаги isolate → adapt → payload → persist → trigger.
- [x] 5.2 В Langfuse: тег и metadata `isolation:on|off`; при `on` span isolate до графа и тег `endpoint:/v1/memory/reset`; нормализация persist как `/v1/sessions/finalize`.
- [x] 5.3 Каждая попытка (включая вторую и далее) пишет isolate и спаны графа в один новый trace; не наследовать OTEL-контекст прошлой попытки.

## 6. Тесты и документы

- [x] 6.1 Тесты: isolate до первой и между попытками; нет reset между persist и trigger; `off` без reset и с warning; `503` → код 1; невалидный флаг → код 2; граф без узла isolate; теги Langfuse.
- [x] 6.2 Обновить README, `.env.example`, `ARCHITECTURE.md`, `docs/product.md`; прогнать pytest, ruff и `openspec validate --change target-adapter --strict`.
