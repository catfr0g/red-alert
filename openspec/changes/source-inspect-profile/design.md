## Context

Каталог атак — готовые YAML под инвест-стенд (YDEX, CUS, картинки). CLI без `--scenario` гоняет все файлы. Исходники стенда Red Alert не читает. Кейс требует шаг «анализ приложения», а типовой прогон — неизвестный репозиторий.

Ограничения: Python 3.14+, без новых обязательных runtime-зависимостей, тесты на фикстурах без живого стенда и без живого харнеса. Планировщик и судья уже ходят в OpenAI-совместимый API.

## Goals / Non-Goals

**Goals:**

- Шаблоны техник с `requires` и слотами; стендовый смысл — в StandProfile.
- `inspect` пишет профиль из исходников, без HTTP стенда.
- `attack` собирает экземпляры, отсекает только заведомо неприменимое, считает ASR по ran.
- Упакованный `invest-stand` сохраняет текущее демо.
- Анализатор за протоколом: фейк в тестах, эвристика, LLM, один харнес.

**Non-Goals:**

- Генерация новых техник вне каталога.
- Донастройка payload во время прогона.
- Три реализации харнеса.
- Inspect живого API.
- Сырые исходники в планировщик и судью.

## Decisions

### Шаблон + профиль, не правка каталога на лету

`attacks/*.yaml` — `AttackTemplate`: текущие поля сценария плюс `requires` и `slots`. Плейсхолдеры `{{slot}}` в текстовых полях. `usable_policy` может содержать плейсхолдеры в списках строк.

`profiles/invest-stand.yaml` — упакованный профиль. `--profile` / `RED_ALERT_PROFILE` перекрывают его.

Сборка: capability `absent`+`high` → skip; пустой слот → skip; иначе подстановка и валидация как у нынешнего `AttackScenario`.

Альтернатива: хранить в каталоге готовые экземпляры и только список `disabled`. Не выбрана: неизвестный репозиторий всё равно получит YDEX в payload.

```mermaid
flowchart LR
    tmpl[AttackTemplate] --> apply[apply_profile]
    prof[StandProfile] --> apply
    apply --> skip[SkippedScenario]
    apply --> inst[AttackScenario]
    inst --> run[run_attack]
```

### Известные capability — закрытый список

`persistent_memory`, `multi_user`, `vision`. Этого достаточно, чтобы отсечь memory / cross-user / image. Нет поля — `unknown`/`low`, шаблон не режем.

`--scenario` обходит только capability. Пустой слот по-прежнему ошибка.

### inspect не ходит на стенд

`red-alert inspect <path> [--output] [--analyzer]`. Ключи стенда не нужны. По умолчанию пишет `stand-profile.yaml` в cwd.

Протокол: `SourceAnalyzer.analyze(path) -> StandProfile`.

Backend:

| id | Когда | Сеть |
|---|---|---|
| `heuristic` | всегда есть; default без ключа | нет |
| `llm` | default при `OPENAI_API_KEY` и `MODEL_ATTACK` | тот же API, что планировщик |
| `harness` | явный `--analyzer harness` | Codex CLI в Docker |

Живой харнес — **Codex** (`codex exec`) внутри одноразового Docker-контейнера. Внешняя команда не меняется: `red-alert inspect <path> --analyzer harness`. Red Alert сам запускает `docker run`, монтирует переданный `<path>` в `/workspace` только для чтения и использует `/workspace` как рабочий каталог Codex. Временный каталог для JSON Schema и `--output-last-message` монтируется отдельно с записью; после запуска он удаляется. Вызов использует `--json`; stdout контейнера построчно пишется с `flush` в `analysis_artifacts/latest_codex_trace.jsonl`, а каждое событие параллельно форматируется с отступами в `analysis_artifacts/latest_codex_trace.log`. Профиль по-прежнему читается из `--output-last-message`. OpenCode и pi в этом change не подключаем.

Образ содержит Codex CLI, системный `/etc/codex/config.toml`, отдельный config profile `red-alert-harness` и системный `/etc/codex/requirements.toml`. Определение custom permission profile находится и в системном config, чтобы allowlist могла проверить его до загрузки именованного profile. Permission profile сначала запрещает весь filesystem через `:root = "deny"`, затем разрешает только чтение `/workspace` и минимальных runtime-путей; `.env` и сеть команд запрещены. `web_search = "disabled"` отдельно выключает hosted search. `approval_policy = "never"` не даёт запросить выход за границы. Запуск использует `--ignore-user-config`, `--strict-config` и `--ephemeral`; старый `--sandbox` и расширяющий workspace `--add-dir` не передаются.

Контейнер получает сеть, необходимую самому Codex для обращения к OpenAI, но не получает переменные OpenAI/Codex с хоста. Для штатной авторизации Red Alert копирует существующий `$CODEX_HOME/auth.json` (или `~/.codex/auth.json`) во временный каталог Codex и монтирует только эту временную копию. Каталог удаляется после запуска. Исходный auth-файл хоста контейнер не видит и изменить не может.

Образ `red-alert-codex-harness:0.153.4-ra1` строится автоматически при первом harness-запуске, если его нет локально. Dockerfile и оба TOML-файла поставляются внутри Python-пакета. Контейнер запускается с `--rm`, read-only root filesystem, отдельным `tmpfs`, без Linux capabilities и с `no-new-privileges`; файловая граница хоста обеспечивается отсутствием других bind mount.

Альтернатива: локальный Codex CLI с permission profile хоста. Не выбрана: корректность системной allowlist зависит от администраторской установки, а ошибка профиля оставляет процесс рядом с остальными файлами хоста. Docker делает список доступных хостовых путей явным через bind mount.

Альтернатива: только харнес. Не выбрана: без Docker `inspect` нельзя потрогать. Эвристика и LLM остаются доступными без контейнера.

Альтернатива: свой краулер без LLM. Не выбрана как единственный путь: на неизвестном репо bindings будут пустые и почти всё отсечется.

### Исходники во внешнюю модель — только явный inspect

`attack` исходники не читает. `inspect --analyzer llm|harness` сам является согласием отправить выбранные файлы. Не читаем `.env`, `.git`, `node_modules`, `.venv`, `__pycache__`, бинарники. В профиль не попадают секреты из этих путей.

`heuristic` и фейк сеть не используют.

### Эвристика и LLM заполняют и capability, и слоты

Эвристика: по дереву и тексту файлов (память / persist / finalize, несколько пользователей, image/vision). Bindings заполняет только если находит явные якоря (иначе пусто → skip при attack). Для неизвестного репо это честно.

LLM: дерево файлов + короткие выдержки из манифестов и кода, ответ — JSON по схеме профиля, валидация Pydantic.

Харнес и LLM получают краткий каталог шаблонов и должны заполнить слоты по коду, а не только capability. Пустые bindings — только если в исходниках нечего привязать.

Харнес: `codex exec --ignore-user-config --profile red-alert-harness --strict-config --ephemeral --output-schema --output-last-message`; если last-message пуст — вытащить JSON из JSONL-трассировки.

### Отчёт

`SkippedScenario(name, reason)` печатается в консоли. JSON: массив `skipped`. `total` / ASR — только попытки `run_attack`. Все шаблоны skipped → код 2, без JSON-отчёта.

Один `--scenario` без skip: как сейчас, `skipped` пустой или отсутствует.

### Тесты

Фейк-анализатор и фикстурные профили. Живой Codex и живой LLM в CI не вызываются. `invest-stand` + шаблоны должны собрать те же смыслы, что проверяют нынешние `test_attacks`.

## Risks / Trade-offs

- [Харнес врёт в bindings] → skip при пустом слоте; `invest-stand` для демо; эвристика не выдумывает слоты.
- [Исходники уходят во внешний API] → только `inspect` + `llm`/`harness`; исключить секреты и мусорные каталоги.
- [BREAKING: каталог больше не экземпляры] → default-профиль `invest-stand`; явный путь к YAML без слотов по-прежнему гоняется.
- [Эвристика слабо заполняет неизвестный репо] → LLM/харнес для слотов; capability-отсечение всё равно экономит прогоны.

## Migration Plan

1. Добавить модели профиля и шаблона, упаковать `invest-stand`.
2. Перевести YAML каталога на слоты, не ломая сборку через default-профиль.
3. `attack --profile`, skip, отчёт.
4. `inspect` и анализаторы.
5. Документация. Откат: вернуть прежние YAML и загрузку без профиля.

## Open Questions

Нет. Харнес — Codex. Исходники во внешнюю модель — только по команде `inspect` с `llm` или `harness`.
