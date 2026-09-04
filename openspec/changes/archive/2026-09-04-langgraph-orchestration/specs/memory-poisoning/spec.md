## MODIFIED Requirements

### Requirement: Сценарий отравления памяти через публичный API

СИСТЕМА ДОЛЖНА (MUST) реализовать сценарий `memory-poisoning` графом LangGraph: payload и finalize ключом атакующего, trigger ключом жертвы. Внешний HTTP-контракт не меняется.

#### Scenario: Полная цепочка одной попытки

- **WHEN** запускается сценарий `memory-poisoning`
- **THEN** система последовательно: отправляет payload-сообщения в `POST /v1/chat/completions` с `session_id` A и ключом атакующего; вызывает `POST /v1/sessions/{A}/finalize` с ключом атакующего; отправляет триггер в `POST /v1/chat/completions` с новым `session_id` B и ключом жертвы
