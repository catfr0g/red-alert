## 1. Модели профиля и шаблона

- [x] 1.1 Добавить StandProfile, capability (`present|absent|unknown`, `high|low`), bindings и загрузку YAML; неизвестная capability в файле — ошибка, отсутствующая в файле — unknown/low.
- [x] 1.2 Расширить загрузку каталога до AttackTemplate (`requires`, `slots`, плейсхолдеры `{{slot}}`); функция apply_profile → экземпляры и skipped.
- [x] 1.3 Упаковать `profiles/invest-stand.yaml` и default-путь; тесты загрузки профиля и отсечения (vision absent, пустой слот, unknown не режет).

## 2. Каталог шаблонов

- [x] 2.1 Перевести YAML в `attacks/` на шаблоны со слотами; стендовые формулировки перенести в invest-stand.
- [x] 2.2 Обновить `test_attacks`: шаблон без YDEX, экземпляр через invest-stand сохраняет прежние проверки.

## 3. Attack CLI и отчёт

- [x] 3.1 `--profile` / `RED_ALERT_PROFILE`, умолчание invest-stand; невалидный файл — код 2.
- [x] 3.2 Без `--scenario` запускать только собранные; все skipped — код 2; `--scenario` обходит capability, пустой слот — код 2.
- [x] 3.3 Печать skipped, JSON-массив `skipped`, ASR только по ran; тесты CLI и отчёта.

## 4. Inspect и анализаторы

- [x] 4.1 Команда `red-alert inspect <path>`: `--output`, `--analyzer`; без HTTP стенда и без ключей стенда; плохой path — код 2.
- [x] 4.2 Протокол SourceAnalyzer; фейк для тестов; heuristic без сети; llm на существующем OpenAI-контуре; harness — Codex CLI; секреты и мусорные каталоги не читать.
- [x] 4.3 Тесты inspect: фейк пишет YAML, нет каталога → 2, .env не попадает в профиль, llm без ключа → 2, нет harness → 1.
- [x] 4.4 Передать каталог слотов в llm/harness; требовать заполненные bindings; разбор JSON из last-message / шумного stdout.

## 5. Документы и проверка

- [x] 5.1 Обновить README, ARCHITECTURE.md, docs/product.md.
- [x] 5.2 Прогнать pytest, ruff, ty и `openspec validate --change source-inspect-profile --strict`.
