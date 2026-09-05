## 1. Скрипты установки

- [x] 1.1 Переписать `install.sh`: Python 3.14+, `venv`, `pip install -r requirements.txt`, `.env` только если нет, обёртка `red-alert` в `~/.local/bin` и PATH. Без `uv`, `--group dev` и `pre-commit`.
- [x] 1.2 Переписать `install.ps1` с тем же сценарием для Windows: `red-alert.cmd` в `%USERPROFILE%\.local\bin` и User PATH.

## 2. Lock для pip и хук

- [x] 2.1 Перенести `pre-commit` из runtime-зависимостей в группу `dev`; обновить lock.
- [x] 2.2 Добавить хук pre-commit `uv export --frozen --no-dev --no-hashes -o requirements.txt` на изменения `uv.lock` / `pyproject.toml` и закоммитить актуальный `requirements.txt`.

## 3. Тесты и документация

- [x] 3.1 Обновить автотесты скриптов и pre-commit: pip/venv/PATH, нет uv/dev/hooks в install; хук экспорта и состав `requirements.txt`. Не запускать живой pip и не менять PATH в тесте.
- [x] 3.2 Обновить `README.md` и `ARCHITECTURE.md`; прогнать pytest, ruff и `openspec validate install-scripts --strict`.

## 4. Bootstrap CPython

- [x] 4.1 В `install.sh` и `install.ps1` при отсутствии или старом Python скачивать pinned `python-build-standalone` 3.14.7 в пользовательский кэш и создавать `.venv` из него.
- [x] 4.2 Обновить автотесты и README: в скриптах есть URL/версия standalone, живую загрузку не запускать; прогнать pytest, ruff и `openspec validate install-scripts --strict`.
