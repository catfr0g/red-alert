## Purpose

Пользовательская установка Red Alert: корневые `install.sh` и `install.ps1` ставят runtime через pip, при необходимости скачивают CPython 3.14 и кладут команду `red-alert` в PATH. Dev-окружение и `uv` остаются в `make setup`.

## Requirements

### Requirement: Корневые скрипты установки для POSIX и Windows

СИСТЕМА ДОЛЖНА (MUST) содержать в корне репозитория файлы `install.sh` и `install.ps1`. `install.sh` предназначен для Linux и macOS. `install.ps1` предназначен для Windows PowerShell.

#### Scenario: Оба файла есть в корне

- **WHEN** просматривают корень репозитория
- **THEN** там есть `install.sh` и `install.ps1`

### Requirement: Скрипт работает из своего каталога

СИСТЕМА ДОЛЖНА (MUST) в каждом скрипте перейти в каталог, где лежит сам скрипт, и считать его корнем репозитория. Если в этом каталоге нет `pyproject.toml`, `requirements.txt` или `.env.example`, скрипт ДОЛЖЕН (MUST) завершиться с ненулевым кодом и не ставить пакет.

#### Scenario: В тексте есть переход в каталог скрипта и проверка корня

- **WHEN** просматривают тексты `install.sh` и `install.ps1`
- **THEN** в каждом есть переход в каталог скрипта и проверка наличия `pyproject.toml` и `requirements.txt`

### Requirement: Пользовательская установка через Python и pip

СИСТЕМА ДОЛЖНА (MUST) в каждом скрипте найти или скачать Python 3.14+, создать `.venv` через `python -m venv`, если его нет, и выполнить `pip install -r requirements.txt`. Скрипты НЕ ДОЛЖНЫ (MUST NOT) вызывать `uv`, `uv sync`, `--group dev` или `pre-commit install`.

#### Scenario: Рецепт установки без uv и dev

- **WHEN** просматривают тексты `install.sh` и `install.ps1`
- **THEN** в каждом есть `venv`, `pip install` и `requirements.txt`, и нет `uv sync`, `--group dev` и `pre-commit install`

### Requirement: Скачивание CPython 3.14 при отсутствии или старой версии

СИСТЕМА ДОЛЖНА (MUST) использовать уже установленный Python 3.14+, если он есть в PATH. Если подходящего интерпретатора нет, скрипт ДОЛЖЕН (MUST) скачать pinned `python-build-standalone` CPython 3.14 в пользовательский кэш и создать `.venv` из него. Живую загрузку автотесты не выполняют.

#### Scenario: В скриптах есть fallback на python-build-standalone

- **WHEN** просматривают тексты `install.sh` и `install.ps1`
- **THEN** в каждом есть `python-build-standalone`, версия `3.14.7` и релиз `20260901`

### Requirement: Команда red-alert появляется в PATH

СИСТЕМА ДОЛЖНА (MUST) после установки зависимостей положить команду `red-alert` в пользовательский каталог `~/.local/bin` (на Windows — `%USERPROFILE%\.local\bin`) и добавить этот каталог в PATH текущей сессии и в постоянный PATH пользователя, если его там ещё нет.

#### Scenario: В скриптах есть установка в .local/bin и PATH

- **WHEN** просматривают тексты `install.sh` и `install.ps1`
- **THEN** в каждом есть `.local/bin` и изменение `PATH`

### Requirement: .env не перезаписывается

СИСТЕМА ДОЛЖНА (MUST) скопировать `.env.example` в `.env` только если `.env` нет. Существующий `.env` не перезаписывать.

#### Scenario: Копирование примера только при отсутствии файла

- **WHEN** просматривают тексты `install.sh` и `install.ps1`
- **THEN** в каждом есть копирование `.env.example` при отсутствии `.env`

### Requirement: Экспорт uv.lock в requirements.txt

СИСТЕМА ДОЛЖНА (MUST) содержать корневой `requirements.txt`, полученный командой `uv export --frozen --no-dev --no-hashes`. В `.pre-commit-config.yaml` ДОЛЖЕН (MUST) быть хук, который запускает эту команду при изменении `uv.lock` или `pyproject.toml`. В экспорте НЕ ДОЛЖНЫ (MUST NOT) быть пакеты группы `dev`.

#### Scenario: Хук и файл экспорта есть

- **WHEN** просматривают `.pre-commit-config.yaml` и корневой `requirements.txt`
- **THEN** в конфиге есть `uv export --frozen --no-dev --no-hashes` и `requirements.txt`, а в `requirements.txt` есть runtime-зависимость `httpx` и нет `pytest`
