# Red Alert — Product (Proof of Concept)

## Что это

CLI-инструмент для автоматизированного red teaming агентных ИИ-систем.
PoC исполняет каталог техник против любой OpenAI-совместимой цели, описанной в StandProfile: инвестиционный стенд, OpenClaw или произвольный агент с chat completions.

Цель PoC — показать, что атака собирается из профиля, а не из зашитого адаптера: один HTTP-исполнитель, разные bindings.

## Целевой пользователь

Специалист департамента кибербезопасности, проверяющий генеративные ИИ-системы банка.

## Как это работает

```
red-alert attack --profile stand-profile.yaml --output attack.log
```

1. **Подключение** — CLI читает binding сценария: `target`, `eval`, `persist` и корневой `reset`.
2. **Атака** — свой LLM пишет payload; `target` получает chat, затем опциональный persist.
3. **Верификация** — LLM-судья смотрит `success_check` и ответы `target` / `eval`.
4. **Отчёт** — в консоли прогресс и ASR; JSON с трейсами успешных атак (`--output`).

## Целевая система (PoC)

Любой агент с OpenAI-совместимым chat endpoint. Для инвест-стенда это обычно `agent-api` на `:8600`. URL, заголовки, model и токены задаются профилем, а не флагами CLI.

## Граница PoC

### Входит

- Шаблоны в YAML (`attacks/`, 18 техник с префиксом MITRE ATLAS `{AML.Txxxx}_{slug}`): отравление памяти, probe, image, BAC, indirect injection и др. Без `--scenario` прогоняются техники, которые собрал профиль (`applicable`, capability, слоты). `red-alert inspect` пишет профиль по исходникам; Codex harness исследует их в одноразовом Docker-контейнере с read-only mount.
- StandProfile: `defaults` для общих endpoint/bearer, `applicable: false` для явного skip, bindings по ATLAS-имени атаки.
- Общий OpenAI-compatible runtime: `target`/`eval`, declarative persist/reset, `${VAR}` из env.
- Адаптивный планировщик: Red Alert ходит в свой LLM (`OPENAI_API_KEY`, `OPENAI_BASE_URL_ATTACK`, `MODEL_ATTACK`) и генерирует следующий payload.
- Верификация: LLM-as-a-judge по `success_check`.
- Отчёт: цветной CLI-итог и JSON с доказательствами успешных попыток.
- Langfuse (опционально): локальный `docker compose up`, живые диалоги попытки.
- Изоляция попыток: `reset` из профиля до каждой попытки (`--isolate on` по умолчанию).

### Не входит (планируется позже)

- Новые графы под инструменты и MCP.
- Генерация новых типов атак, которых нет в каталоге.
- UI / dashboard.

## Стек

| Компонент | Технология |
|---|---|
| Язык | Python 3.14+ |
| Оркестрация атаки | LangGraph |
| Наблюдаемость | Langfuse (локальный docker-compose) |
| HTTP-клиент | httpx |
| Модели данных | Pydantic |
| Линтер | ruff |
| Типы | ty |
| Тесты | pytest |

## Верификация успеха атаки

LLM-судья получает `success_check`, `target_response` и опциональный `eval_response`. Для `memory` обычно оценивается новая сессия eval. Для `probe` — ответ target, плюс eval если в профиле задан `eval.prompt`.

## Метрика

**Attack Success Rate (ASR)** — доля успешных атак из общего числа попыток.

## Эволюция продукта

```
PoC (текущий)          → Расширение атак           → Расширение целей
─────────────────────    ─────────────────────────    ──────────────────────────
YAML-driven runtime      N типов атак                 новые каналы и MCP
inspect + attack         новые payload-каналы         полный цикл с отчётом
LLM-as-a-judge           CLI + HTML/JSON
```

## Связь с целью

Red Alert **не содержит** код цели. Цель — внешняя зависимость, которая:
- живёт в отдельном репозитории;
- запускается и обновляется независимо;
- подключается через StandProfile: endpoint, headers, body и имена env с токенами.
