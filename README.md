# Red Alert

CLI для авторизованного red teaming агентных ИИ-систем.

Атаки собираются из YAML-шаблонов в `attacks/` и исполняются по StandProfile: endpoint, credentials, persist и reset берутся только из профиля. Неизвестный репозиторий сначала разбирает `red-alert inspect`. Цель должна быть OpenAI-совместимой как минимум на chat completions.

Только изолированный стенд. Без боевых счетов, ключей и персональных данных.

## Требования

- Python 3.14+ (если его нет, `install.sh` / `install.ps1` скачает portable CPython)
- StandProfile YAML (`--profile` / `RED_ALERT_PROFILE`)
- Значения env, на которые ссылается профиль (`bearer_env` и `${VAR}`)
- Ключ OpenAI-совместимого API для планировщика и судьи (`OPENAI_API_KEY`, `MODEL_ATTACK`, `MODEL_JUDGE`)

## Установка

Linux и macOS:

```bash
./install.sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Скрипт находит Python 3.14+ или скачивает portable CPython 3.14.7 (`python-build-standalone`) в пользовательский кэш. Затем создаёт `.venv`, ставит runtime-зависимости из `requirements.txt` через pip, копирует `.env.example` в `.env`, если `.env` ещё нет, и добавляет команду `red-alert` в PATH (`~/.local/bin`). Существующий `.env` не трогает. После установки откройте новый терминал или проверьте, что `~/.local/bin` есть в PATH.

Для разработки нужны [uv](https://docs.astral.sh/uv/) и GNU Make: `make setup` ставит dev-группу и git-хуки. Список целей: `make`.

## Конфигурация

Скопируйте `.env.example` в `.env`. Нужны профиль цели и отдельный ключ LLM планировщика. `.env` не коммитится. Аргументы CLI перекрывают `.env`.

Bearer-токены цели не задаются флагами: профиль указывает имена переменных в `target.bearer_env` / `eval.bearer_env`, а также любые `${VAR}` в URL, headers и body.

| Источник | Переменная / флаг | Назначение |
|---|---|---|
| Профиль | `--profile` / `RED_ALERT_PROFILE` | StandProfile YAML. Обязателен для `attack` |
| Цель | поля binding `target` / `eval` | HTTP endpoint, model, custom_body/headers, bearer_env |
| Планировщик | `OPENAI_API_KEY` | Ключ OpenAI-совместимого API, не ключ цели |
| Планировщик | `OPENAI_BASE_URL_ATTACK` | База атакующей LLM, по умолчанию OpenRouter |
| Планировщик | `MODEL_ATTACK` | Имя атакующей модели |
| Судья | `OPENAI_BASE_URL_JUDGE` | Отдельная база LLM-судьи |
| Судья | `MODEL_JUDGE` | Имя модели-судьи |
| Планировщик | `MAX_TOKENS` | Лимит ответа планировщика, по умолчанию `2048` |
| Сценарий | `--scenario` | Один YAML (имя или путь). Без флага — применимые атаки каталога |
| Каталог | `--attacks-dir` / `RED_ALERT_ATTACKS_DIR` | Папка с шаблонами атак, по умолчанию `attacks/` |
| Изоляция | `--isolate` / `RED_ALERT_ISOLATE` | `on` (по умолчанию) выполняет `reset` из профиля, `off` не трогает состояние |
| Попытки | `--attempts` | Число прогонов для ASR |
| Отчёт | `--output` / `-o` | JSON с трейсами успешных атак (UTF-8) |
| Debug | `--debug` / `RED_ALERT_DEBUG` | Полный лог шагов на stderr; в JSON все попытки |
| Langfuse | `RED_ALERT_LANGFUSE` | `1` / `true` / `yes` / `on` — писать все попытки в Langfuse |
| Langfuse | `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | Ключи проекта (обязательны, если экспорт включён) |
| Langfuse | `LANGFUSE_BASE_URL` | По умолчанию `http://localhost:3000` |

## Разбор исходников

```bash
uv run red-alert inspect ../stand-new --output stand-profile.yaml
```

`inspect` не ходит на живую цель и не требует её ключей. `--analyzer heuristic` только читает файлы и не подставляет стендовые слоты. `llm` и `harness` получают каталог техник и должны заполнить слоты, `target`/`eval`/`persist` и опциональный `reset` из исходников. Без флага при наличии `OPENAI_API_KEY` и `MODEL_ATTACK` используется `llm`. Дополнительный операторский контекст: `--context CONTEXT.md`.

При `--analyzer harness` поток Codex пишется во время анализа: исходный JSONL — в `analysis_artifacts/latest_codex_trace.jsonl`, версия с отступами для чтения — в `analysis_artifacts/latest_codex_trace.log`.

Для `harness` нужны запущенный Docker и выполненный на хосте `codex login`. Команда остаётся обычной:

```bash
uv run red-alert inspect ../stand-new --analyzer harness --output stand-profile.yaml
```

При первом запуске Red Alert автоматически собирает локальный образ `red-alert-codex-harness:0.153.4-ra1`. Указанный каталог монтируется в контейнер как `/workspace` только для чтения. Корневая файловая система контейнера тоже read-only; запись доступна только во временные mount и `tmpfs`. Кроме отдельного временного каталога для результата и временной копии `auth.json`, другие пути хоста контейнеру не передаются. Временные файлы удаляются после анализа.

Внутри образа находятся Codex CLI, `red-alert-harness` и системная allowlist. Профиль запрещает `.env`, `.git`, `node_modules`, `.venv`, `__pycache__`, сеть shell-команд и hosted web search; `approval_policy = "never"` запрещает расширение прав. Сеть самого контейнера остаётся включённой, иначе Codex не сможет обратиться к OpenAI. Переменные `OPENAI_*` и `CODEX_*` с хоста в контейнер не передаются.

```bash
uv run red-alert attack --profile stand-profile.yaml --output attack-report.json
```

Без `--profile` или `RED_ALERT_PROFILE` атака не запускается. Отсекаются атаки с `absent` capability и высокой уверенностью, пустым слотом или `target.endpoint: null`. `--scenario` обходит отсечение по capability.

## Запуск

```bash
make attack ARGS='--profile stand-profile.yaml --output attack-report.json --attempts 3'
```

То же самое: `uv run red-alert attack --profile stand-profile.yaml --output attack-report.json --attempts 3`.

Без `--scenario` CLI проходит применимые YAML в `attacks/` по алфавиту. `--attempts` — число попыток **каждого** сценария.

По умолчанию перед каждой попыткой выполняется `reset` из профиля, если он задан. Если `reset: null`, изоляция — no-op. Чтобы оставить грязное состояние: `--isolate off` (будет warning в stderr).

В терминале — цветной прогресс и краткий ASR. Трейсы успешных попыток пишутся в JSON. Без `--output` JSON печатается в stdout. Не редиректите `>` в PowerShell: получится UTF-16.

Для разбора прогона: `uv run red-alert attack --profile stand-profile.yaml --debug`. На stderr будут тела `isolate`, `adapt`, payload, persist и eval; в JSON попадут и неуспешные попытки.

Перед каждым inject планировщик вызывает свой LLM и пишет payload по цели из YAML.

Готовые сценарии в `attacks/`:

- `memory-poisoning` и варианты — persist, затем eval в новой сессии;
- `cross-user-portfolio` — probe: ответ target, опционально отдельный eval;
- `system-prompt-leakage` / `base64-injection` / `openclaw-goal-hijack` — probe-векторы.

```bash
uv run red-alert attack --profile stand-profile.yaml --scenario memory-poisoning
uv run red-alert attack --profile stand-profile.yaml --scenario cross-user-portfolio
uv run red-alert attack --profile stand-profile.yaml --scenario ./attacks/memory-poisoning.yaml
```

Код выхода: `0` если прогон завершён (в том числе при ASR 0%), `1` если Langfuse включён и не работает, `2` при ошибке ввода.

## Langfuse

Локальный Langfuse поднимается из корня репозитория (это не compose цели):

```bash
make langfuse-up
```

Остановить, сохранив данные: `make langfuse-down`. То же самое: `docker compose up -d` / `docker compose down`.

UI: `http://localhost:3000`. Redis/Postgres/ClickHouse на хост не публикуются. Headless init создаёт проект с ключами `pk-lf-local-dev` / `sk-lf-local-dev`. В `.env`:

```
RED_ALERT_LANGFUSE=1
LANGFUSE_PUBLIC_KEY=pk-lf-local-dev
LANGFUSE_SECRET_KEY=sk-lf-local-dev
LANGFUSE_BASE_URL=http://localhost:3000
```

Без `RED_ALERT_LANGFUSE` экспорт выключен. Если флаг включён, а Langfuse недоступен — CLI останавливается с кодом 1, JSON-отчёт не печатается. Граф попытки пишется в реальном времени. В Langfuse это диалоги (планировщик ↔ target, затем eval), не dump внутреннего state. У trace — теги исхода, фактические path цели и `vulnerability` из YAML.

## Проверки

```bash
make check
```

То же самое: `uv run pytest`, `uv run ruff check .`, `uv run ty check`. Формат: `make fmt` или `uv run ruff format .`. Хуки целиком: `uv run pre-commit run --all-files`.

Хуки: ruff, ty, pytest.

## Документация

- [ARCHITECTURE.md](ARCHITECTURE.md) — модули и поток атаки
- [docs/product.md](docs/product.md) — границы PoC
- [docs/business/](docs/business/) — контекст кейса
- [openspec/specs/](openspec/specs/) — основные спецификации
