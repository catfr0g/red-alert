# Red Alert

CLI для авторизованного red teaming агентных ИИ-систем.

PoC ходит на тестовый стенд [GenAI Investment Assistant](../genai-invest-agent-memory-stand/). Атаки описаны в YAML (`attacks/`): отравление памяти, probe на чужой портфель и любые свои файлы с той же схемой.

Только изолированный стенд. Без боевых счетов, ключей и персональных данных.

## Требования

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)
- Запущенный стенд `agent-api` (по умолчанию `http://localhost:8600`)
- Два разных API-ключа стенда (атакующий и жертва, например `client1001` и `client1002`)
- Ключ OpenAI-совместимого API для планировщика атак и судьи (`OPENAI_API_KEY`, `MODEL_ATTACK`, `MODEL_JUDGE`)

## Установка

```bash
make setup
```

То же самое вручную: `uv sync --group dev` и `uv run pre-commit install`. Если `.env` нет, `make setup` копирует его из `.env.example`.

Список целей: `make`. Нужен GNU Make (у Windows часто идёт вместе с Git/gcc).

## Конфигурация

Скопируйте `.env.example` в `.env`. Нужны ключи стенда и отдельный ключ LLM планировщика. `.env` не коммитится.

Ключи стенда должны принадлежать разным пользователям. Аргументы CLI перекрывают `.env`.

После переподнятия стенда ключи пропадают. Их заново выпускает скрипт — без ручного SSO:

```bash
make keys
```

То же самое: `uv run python script/fetch_stand_keys.py`.

По умолчанию это `client1001` (атакующий) и `client1002` (жертва). Адрес стенда, Keycloak и список пользователей задаются флагами или переменными, см. `.env.example`. Дополнительные логины сохраняются как `RED_ALERT_USER_<login>_API_KEY` — прогон атак их пока не читает.

| Источник | Переменная / флаг | Назначение |
|---|---|---|
| Цель | `RED_ALERT_TARGET` / `--target` | Базовый URL `agent-api` |
| Атакующий | `RED_ALERT_API_KEY` / `--api-key` | Bearer клиента, который травит память |
| Жертва | `RED_ALERT_VICTIM_API_KEY` / `--victim-api-key` | Bearer другого клиента |
| Планировщик | `OPENAI_API_KEY` | Ключ OpenAI-совместимого API, не ключ стенда |
| Планировщик | `OPENAI_BASE_URL_ATTACK` | База атакующей LLM, по умолчанию OpenRouter |
| Планировщик | `MODEL_ATTACK` | Имя атакующей модели, например `openai/gpt-5-mini` |
| Судья | `OPENAI_BASE_URL_JUDGE` | Отдельная база LLM-судьи, по умолчанию OpenRouter |
| Судья | `MODEL_JUDGE` | Имя модели-судьи |
| Планировщик | `MAX_TOKENS` | Лимит ответа планировщика, по умолчанию `2048` |
| Сценарий | `--scenario` | Один YAML (имя или путь). Без флага — все файлы в каталоге |
| Каталог | `--attacks-dir` / `RED_ALERT_ATTACKS_DIR` | Папка с атаками, по умолчанию `attacks/` |
| Режим стенда | `--auth-mode` / `RED_ALERT_AUTH_MODE` | `vulnerable`, `protected` или `both` |
| Изоляция | `--isolate` / `RED_ALERT_ISOLATE` | `on` (по умолчанию) или `off`. `on` сбрасывает память стенда до каждой попытки |
| Попытки | `--attempts` | Число прогонов для ASR |
| Отчёт | `--output` / `-o` | JSON с трейсами успешных атак (UTF-8) |
| Debug | `--debug` / `RED_ALERT_DEBUG` | Полный лог шагов на stderr; в JSON все попытки |
| Langfuse | `RED_ALERT_LANGFUSE` | `1` / `true` / `yes` / `on` — писать все попытки в Langfuse |
| Langfuse | `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | Ключи проекта (обязательны, если экспорт включён) |
| Langfuse | `LANGFUSE_BASE_URL` | По умолчанию `http://localhost:3000` |

## Запуск

```bash
make attack ARGS='--output attack-report.json --attempts 3'
```

То же самое: `uv run red-alert attack --output attack-report.json --attempts 3`.

Без `--scenario` CLI проходит все YAML в `attacks/` по алфавиту. `--attempts` — число попыток **каждого** сценария. В баре видно текущее имя и режим стенда.

Чтобы сравнить дырявый и защищённый режим стенда:

```bash
uv run red-alert attack --auth-mode both --output attack-report.json --attempts 3
```

Сначала все выбранные атаки идут с `auth_mode=vulnerable`, затем те же — с `protected`. В итоге будет ASR по каждому режиму.

По умолчанию перед каждой попыткой CLI вызывает isolate на стенде (`POST /v1/memory/reset`): глобальная очистка памяти агента у всех клиентов стенда, без ключей и инвестиционных данных. Так повторные попытки и сравнение режимов не наследуют прошлое отравление. Чтобы оставить грязное состояние: `--isolate off` (будет warning в stderr).

В терминале — цветной прогресс и краткий ASR. Трейсы успешных попыток пишутся в JSON. Без `--output` JSON печатается в stdout. Не редиректите `>` в PowerShell: получится UTF-16.

Для разбора прогона: `uv run red-alert attack --debug`. На stderr будут тела `isolate`, `adapt`, payload, persist и trigger; в JSON попадут и неуспешные попытки.

Перед каждым inject планировщик вызывает свой LLM и пишет payload по цели из YAML.

Готовые сценарии в `attacks/`. В каждом YAML в комментариях расписаны поля:

- `memory-poisoning` — отравление памяти, жертва должна советовать продать `YDEX`;
- `memory-poisoning-peer-exfil` — global policy заставляет в ответ жертве вставить эталон CUS 1001 (SBER/GAZP);
- `memory-poisoning-sleeper` — спящая policy: на «подушку безопасности» советовать ликвидацию на депозит;
- `cross-user-portfolio` — probe: агент выдаёт портфель другого клиента;
- `system-prompt-leakage` — probe: утечка system prompt / внутренних инструкций (LLM07);
- `base64-injection` — probe: скрытый запрос в base64, агент декодирует и исполняет (LLM01).

```bash
uv run red-alert attack --scenario memory-poisoning
uv run red-alert attack --scenario cross-user-portfolio
uv run red-alert attack --scenario ./attacks/memory-poisoning.yaml
```

Код выхода: `0` если прогон завершён (в том числе при ASR 0%), `1` если Langfuse включён и не работает, `2` при ошибке ввода.

## Langfuse

Локальный Langfuse поднимается из корня репозитория (это не compose стенда):

```bash
make langfuse-up
```

Остановить, сохранив данные: `make langfuse-down`. То же самое: `docker compose up -d` / `docker compose down`.

UI: `http://localhost:3000`. Redis/Postgres/ClickHouse на хост не публикуются — иначе пересекаются со стендом (`:6379`). Headless init создаёт проект с ключами `pk-lf-local-dev` / `sk-lf-local-dev`. В `.env`:

```
RED_ALERT_LANGFUSE=1
LANGFUSE_PUBLIC_KEY=pk-lf-local-dev
LANGFUSE_SECRET_KEY=sk-lf-local-dev
LANGFUSE_BASE_URL=http://localhost:3000
```

Без `RED_ALERT_LANGFUSE` экспорт выключен. Если флаг включён, а Langfuse недоступен — CLI останавливается с кодом 1, JSON-отчёт не печатается. Граф попытки пишется в реальном времени. В Langfuse это диалоги (планировщик ↔ стенд, затем жертва), не dump внутреннего state. У trace — теги исхода, ручки стенда и `vulnerability` из YAML.

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
