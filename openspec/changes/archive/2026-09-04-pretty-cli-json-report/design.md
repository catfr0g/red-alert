## Context

Прогон может идти минуты: до 8 inject и trigger с тулами стенда. Пользователь смотрит в терминал. Разбор доказательства удобнее в JSON.

```mermaid
flowchart TD
    graph[LangGraph] --> cb[on_step]
    cb --> bar[rich Progress]
    graph --> report[RunReport]
    report --> summary[Цветной итог]
    report --> json[traces успешных]
```

## Goals / Non-Goals

**Goals:**

- Прогресс: какая попытка и какой шаг сейчас.
- Итог: ASR, success/failure по попыткам, без полного дампа тел.
- JSON: scenario, target, счётчики, ASR, массив `traces` только с `success=true`.
- `--output` пишет этот JSON в UTF-8.

**Non-Goals:**

- Интерактивный TUI.
- JSON неуспешных цепочек.

## Decisions

### rich, не самописные ANSI

`rich` даёт Progress, цвет и отключение цвета, если нет TTY.

### Прогресс в stderr, итог в stdout

Чтобы прогресс не смешивался с JSON, когда файл не задан. Ошибки ввода по-прежнему в stderr.

### Callback из графа

`run_attack` / `run_attempt` принимают `on_step`. Узлы вызывают его после каждого шага. Без callback поведение как сейчас.

### JSON только успешные traces

Неуспех виден в консольном итоге (последний шаг и ошибка). Файл остаётся разбором сработавших атак.

Альтернатива: оставить текстовый дамп. Не выбрано: пользователь просил цвета, прогресс и JSON.

## Risks / Trade-offs

- [В тестах нет TTY] → rich без цвета, строки ASR сохраняем.
- [Пустой traces при ASR 0] → ожидаемо.
