## Context

Сейчас граф и runner ходят в два `StandClient` с зашитыми ручками инвест-стенда: чат с `auth_mode` и `POST /v1/sessions/{id}/finalize`. Между попытками меняются только `session_id`. Долговременная память (в том числе `agent_policy_memories`) копится. Поэтому ASR после первого успешного memory-poisoning завышен: следующая попытка стартует уже из отравленного состояния. То же ломает сравнение `vulnerable` / `protected` и прогон всего каталога.

Стенд добавил `POST /v1/memory/reset`: глобальная очистка Redis (working) и четырёх коллекций Mongo, без ключей и инвестиционных данных. `200 {status: reset}` либо `503 {status: reset_failed}`. Стенд сам запрещает звать reset между атакующим и жертвой одной атаки.

Класть эту ручку третьим методом в `StandClient` закрепит HTTP-контракт одного стенда. У Hermes `/reset` только открывает новую сессию и перечитывает `MEMORY.md`; у OpenClaw `sessions.reset` архивирует диалог. Это не тот же контракт.

## Goals / Non-Goals

**Goals:**

- Вынести цель за протокол `Target`: `chat`, `persist`, `isolate`.
- Реализовать один адаптер — инвест-стенд.
- Изолировать попытки: `isolate()` до каждой попытки, если режим `on`.
- Сохранить грязный режим `--isolate off` с обязательным warning.
- Режим изоляции видеть в CLI, JSON и Langfuse.
- Сбой isolate не считать неуспешной атакой и не портить ASR.

**Non-Goals:**

- Адаптеры Hermes / OpenClaw.
- Каталог стендов и шаблоны URL в YAML.
- Поле reset/isolate в YAML атак.
- Snapshot/restore и очистка одного пользователя.
- Повторный вызов isolate при `503` внутри одного прогона.

## Decisions

### Протокол цели, не набор HTTP-путей

Публичный шов — `Target`:

- `chat(principal, session_id, text)` — сообщение пользователя и ответ агента;
- `persist(principal, session_id)` — зафиксировать сессию в долговременной памяти;
- `isolate()` — вернуть цель к чистому baseline.

`principal` — `attacker` или `victim`. Один объект цели держит оба ключа. Граф больше не получает два клиента.

Инвест-адаптер (`InvestStandTarget`) внутри может оставить текущий HTTP-клиент: чат → `/v1/chat/completions`, persist → `/v1/sessions/{id}/finalize`, isolate → `/v1/memory/reset` (Bearer атакующего). Снаружи граф и runner не знают этих путей.

Альтернатива: YAML с шаблонами path/method. Не выбрана: это всё ещё HTTP-форма этого стенда, OpenClaw и Hermes туда не встанут.

Альтернатива: только метод `reset()` на `StandClient`. Не выбрана: граф так и останется про finalize и два клиента.

```mermaid
flowchart TD
    runner[runner] -->|isolate до попытки| target[Target]
    graph[граф попытки] -->|chat persist| target
    target --> invest[InvestStandTarget]
    invest --> chat["POST /v1/chat/completions"]
    invest --> persist["POST /v1/sessions/id/finalize"]
    invest --> reset["POST /v1/memory/reset"]
```

Второй адаптер в этом change не пишем. Когда появится Hermes, он реализует тот же протокол: persist может быть no-op, isolate — wipe файлов или новый home, а не их `/reset`.

### Isolate живёт в runner, не в графе

`isolate()` вызывается в `run_attack` перед каждой попыткой: первая попытка сценария, следующие попытки, смена YAML, смена `auth_mode`. Внутри попытки граф не трогает isolate. Цикл `adapt → inject → persist` до `usable_policy` по-прежнему копит состояние *этой* атаки.

```mermaid
flowchart TD
    start[попытка] --> iso{isolate on?}
    iso -->|да| call[target.isolate]
    call -->|ошибка| abort[код 1, не в ASR]
    call -->|ok| graph[граф]
    iso -->|нет| graph
    graph --> next{ещё попытка?}
    next -->|да| start
    next -->|нет| report[отчёт]
```

Альтернатива: узел графа `isolate`. Не выбрана: легко сбросить память между persist и trigger и уничтожить саму атаку.

Заметки планировщика (`prior_notes`) между попытками сохраняются. Это память атакующего LLM, не состояние стенда.

### Режим `on` по умолчанию, `off` с warning

Разбор как у debug/Langfuse: `--isolate` перекрывает `RED_ALERT_ISOLATE`, иначе `on`. Допустимы `on` и `off` (без регистра). Иное значение — код 2, без HTTP.

При `off` CLI один раз до первого HTTP пишет в stderr warning: попытки могут наследовать память, ASR не независим. Прогон продолжается.

При `on` isolate обязателен. `200` и `status=reset` — можно начинать попытку. Сеть, HTTP 4xx/5xx, тело без `status=reset` — `IsolateError`, код 1, JSON-отчёт атаки не печатать (как при сбое Langfuse). Попытку в ASR не класть.

Ключ для isolate — атакующего. Третьего секрета нет.

### Persist вместо finalize в графе

Узел, шаг отчёта и диалог Langfuse называются `persist`. Развилка — `after_persist`. Для инвест-стенда это тот же finalize: тело ответа по-прежнему проверяется через `usable_policy`, URL остаётся в шаге.

`flow: probe` persist не вызывает. Isolate при `on` для probe тоже выполняется: каталог и режимы не должны течь друг в друга.

Альтернатива: оставить имя `finalize` в графе. Не выбрана: это имя механизма одного стенда.

### Доказательства и Langfuse

`RunReport.isolation` — `on` или `off`. Краткий итог печатает режим.

При `on` первая запись в `steps` попытки — шаг `isolate` (метод, URL, тело ответа, статус). Затем `adapt` и дальше. При `off` шага isolate нет.

Langfuse:

- тег `isolation:on` или `isolation:off` на каждой попытке;
- metadata `isolation` с тем же значением;
- при `on` после успешного isolate — тег `endpoint:/v1/memory/reset` (нормализованный путь);
- узел/диалог persist вместо finalize; нормализация `/v1/sessions/{id}/finalize` → `/v1/sessions/finalize` как сейчас.

Каждая попытка сначала открывает свой корневой span и свой OTEL-контекст. Isolate и CallbackHandler графа получают `trace_id` этого корня, поэтому не наследуют закрытый span прошлой попытки. Вызов isolate — дочерний span того же trace, до `graph.stream`. В граф его не кладём.

### Тесты

Живой стенд не нужен. `httpx.MockTransport` отвечает на chat, persist и reset. Проверяем: isolate до первой попытки и между попытками; при `off` reset нет и есть warning; `503` останавливает прогон; граф содержит `persist` и не содержит `isolate`; memory-цепочка не зовёт reset между persist и trigger.

## Risks / Trade-offs

- [Глобальный reset на общем стенде сотрёт чужую память] → Только авторизованный тестовый стенд. В README явно: isolate разрушает память агента у всех клиентов стенда.
- [Режим `off` снова завысит ASR] → Default `on`. Warning обязателен. В Langfuse и JSON режим виден.
- [JSON-отчёты со шагом `finalize` перестанут совпадать] → Имя шага теперь `persist`. Это сознательная смена контракта; URL в шаге прежний.
- [Частичный `reset_failed` оставит стенд в неизвестном состоянии] → Прогон стоп. Следующий запуск с `on` снова вызовет isolate.
- [Протокол без второго адаптера кажется лишним] → Цена маленькая, а иначе reset сразу станет третьей зашитой ручкой.

## Migration Plan

Поведение CLI по умолчанию меняется: перед попытками идёт reset стенда. Старые прогоны без изоляции — только `--isolate off`. Откат — вернуть `StandClient` в граф и убрать isolate.

## Open Questions

Нет. Решения зафиксированы: default `on`, warning при `off`, протокол `Target` сразу, без адаптеров других стендов в этом change.
