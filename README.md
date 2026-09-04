# Red Alert

CLI для авторизованного red teaming агентных ИИ-систем.

PoC ходит на тестовый стенд [GenAI Investment Assistant](../genai-invest-agent-memory-stand/). Атаки описаны в YAML (`attacks/`): отравление памяти, probe на чужой портфель и любые свои файлы с той же схемой.

Только изолированный стенд. Без боевых счетов, ключей и персональных данных.

## Требования

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)
- Запущенный стенд `agent-api` (по умолчанию `http://localhost:8600`)
- Два разных API-ключа стенда (атакующий и жертва, например `client1001` и `client1002`)
- Ключ OpenAI-совместимого API для планировщика атак (`OPENAI_API_KEY`, `MODEL`)

## Установка

```bash
uv sync --group dev
uv run pre-commit install
```

## Конфигурация

Скопируйте `.env.example` в `.env`. Нужны ключи стенда и отдельный ключ LLM планировщика. `.env` не коммитится.

Ключи стенда должны принадлежать разным пользователям. Аргументы CLI перекрывают `.env`.

| Источник | Переменная / флаг | Назначение |
|---|---|---|
| Цель | `RED_ALERT_TARGET` / `--target` | Базовый URL `agent-api` |
| Атакующий | `RED_ALERT_API_KEY` / `--api-key` | Bearer клиента, который травит память |
| Жертва | `RED_ALERT_VICTIM_API_KEY` / `--victim-api-key` | Bearer другого клиента |
| Планировщик | `OPENAI_API_KEY` | Ключ OpenAI-совместимого API, не ключ стенда |
| Планировщик | `OPENAI_BASE_URL` | База LLM, по умолчанию OpenRouter |
| Планировщик | `MODEL` | Имя модели, например `openai/gpt-5-mini` |
| Планировщик | `MAX_TOKENS` | Лимит ответа планировщика, по умолчанию `2048` |
| Сценарий | `--scenario` | Один YAML (имя или путь). Без флага — все файлы в каталоге |
| Каталог | `--attacks-dir` / `RED_ALERT_ATTACKS_DIR` | Папка с атаками, по умолчанию `attacks/` |
| Режим стенда | `--auth-mode` / `RED_ALERT_AUTH_MODE` | `vulnerable`, `protected` или `both` |
| Попытки | `--attempts` | Число прогонов для ASR |
| Отчёт | `--output` / `-o` | JSON с трейсами успешных атак (UTF-8) |
| Debug | `--debug` / `RED_ALERT_DEBUG` | Полный лог шагов на stderr; в JSON все попытки |

## Запуск

```bash
uv run red-alert attack --output attack-report.json --attempts 3
```

Без `--scenario` CLI проходит все YAML в `attacks/` по алфавиту. `--attempts` — число попыток **каждого** сценария. В баре видно текущее имя и режим стенда.

Чтобы сравнить дырявый и защищённый режим стенда:

```bash
uv run red-alert attack --auth-mode both --output attack-report.json --attempts 3
```

Сначала все выбранные атаки идут с `auth_mode=vulnerable`, затем те же — с `protected`. В итоге будет ASR по каждому режиму.

В терминале — цветной прогресс и краткий ASR. Трейсы успешных попыток пишутся в JSON. Без `--output` JSON печатается в stdout. Не редиректите `>` в PowerShell: получится UTF-16.

Для разбора прогона: `uv run red-alert attack --debug`. На stderr будут тела `adapt`, payload, finalize и trigger; в JSON попадут и неуспешные попытки.

Перед каждым inject планировщик вызывает свой LLM и пишет payload по цели из YAML.

Готовые сценарии в `attacks/`. В каждом YAML в комментариях расписаны поля:

- `memory-poisoning` — отравление памяти, жертва должна советовать продать `YDEX`;
- `cross-user-portfolio` — probe: агент выдаёт портфель другого клиента.

```bash
uv run red-alert attack --scenario memory-poisoning
uv run red-alert attack --scenario cross-user-portfolio
uv run red-alert attack --scenario ./attacks/memory-poisoning.yaml
```

Код выхода: `0` если прогон завершён (в том числе при ASR 0%), `2` при ошибке ввода.

## Проверки

```bash
uv run pytest
uv run ruff check .
uv run pre-commit run --all-files
```

Хуки: ruff, ty, pytest.

## Документация

- [ARCHITECTURE.md](ARCHITECTURE.md) — модули и поток атаки
- [docs/product.md](docs/product.md) — границы PoC
- [docs/business/](docs/business/) — контекст кейса
- [openspec/specs/](openspec/specs/) — основные спецификации
