## ADDED Requirements

### Requirement: Команда inspect читает исходники и пишет профиль

СИСТЕМА ДОЛЖНА (MUST) предоставлять команду `red-alert inspect <path>`: каталог исходников обязателен, живой HTTP стенда не вызывается, ключи стенда не требуются. Результат — StandProfile в YAML. Путь записи: `--output` / `-o`, иначе `stand-profile.yaml` в текущем каталоге. Несуществующий path или не каталог — код 2 без записи профиля.

#### Scenario: Успешный inspect пишет YAML

- **WHEN** пользователь выполняет `red-alert inspect <существующий-каталог> --output profile.yaml` с фейковым анализатором
- **THEN** процесс завершается с кодом 0, файл `profile.yaml` содержит `capabilities` и `bindings`, HTTP к `:8600` нет

#### Scenario: Каталога нет

- **WHEN** пользователь указывает путь, которого нет
- **THEN** система пишет ошибку в stderr, не создаёт профиль и завершается с кодом 2

#### Scenario: inspect не требует ключи стенда

- **WHEN** не заданы `RED_ALERT_API_KEY` и `RED_ALERT_VICTIM_API_KEY`
- **THEN** `red-alert inspect` всё равно выполняется, если анализатор не требует иных секретов

### Requirement: Анализатор за протоколом

СИСТЕМА ДОЛЖНА (MUST) получать профиль через протокол анализатора (`analyze(path) -> StandProfile`). В тестах используется фейк. Живые backend: `heuristic` (только локальные файлы), `llm` (OpenAI-совместимый API, те же `OPENAI_API_KEY` / `MODEL_ATTACK`), `harness` (Codex CLI в Docker). `--analyzer` выбирает backend. Без флага: `llm`, если есть ключ и модель атаки, иначе `heuristic`. Сырые исходники в планировщик атаки и судью не передаются.

#### Scenario: Фейк в тесте

- **WHEN** в `inspect` подставлен фейк-анализатор с фиксированным профилем
- **THEN** записанный YAML совпадает с этим профилем

#### Scenario: Эвристика не ходит в сеть

- **WHEN** `--analyzer heuristic` и в каталоге есть файлы с признаками памяти и без vision
- **THEN** профиль помечает `persistent_memory` как present и `vision` как absent или unknown, HTTP-запросов нет

#### Scenario: LLM без ключа

- **WHEN** `--analyzer llm` и нет `OPENAI_API_KEY`
- **THEN** система не пишет профиль, пишет ошибку в stderr и завершается с кодом 2

#### Scenario: Сбой харнеса

- **WHEN** `--analyzer harness` и Docker/Codex CLI отсутствует или завершается ошибкой
- **THEN** система не пишет профиль, пишет ошибку в stderr и завершается с кодом 1

### Requirement: Харнес сохраняет трассировку Codex

СИСТЕМА ДОЛЖНА (MUST) запускать Codex CLI с JSONL-выводом и во время работы построчно сохранять stdout последнего запуска в `analysis_artifacts/latest_codex_trace.jsonl`. Система ДОЛЖНА (MUST) параллельно писать читаемую версию событий с JSON-отступами в `analysis_artifacts/latest_codex_trace.log`. Файл профиля ДОЛЖЕН (MUST) по-прежнему формироваться из `--output-last-message`. Каталог трассировок не должен попадать в Git.

#### Scenario: Успешный харнес пишет JSONL

- **WHEN** `codex exec` успешно возвращает JSONL-события и итоговый профиль
- **THEN** JSONL-события доступны в `latest_codex_trace.jsonl` до завершения процесса, читаемая версия записана в `latest_codex_trace.log`, а `inspect` пишет StandProfile

#### Scenario: Харнес завершился с ошибкой

- **WHEN** `codex exec` успел вернуть JSONL-события, но завершился с ненулевым кодом
- **THEN** полученная трассировка сохраняется перед возвратом ошибки

### Requirement: Харнес ограничен каталогом исходников

СИСТЕМА ДОЛЖНА (MUST) запускать Codex в одноразовом Docker-контейнере с read-only root filesystem и config profile `red-alert-harness`, игнорировать общий пользовательский config и не передавать старые `--sandbox` и `--add-dir`. Переданный в `inspect` каталог ДОЛЖЕН (MUST) монтироваться в `/workspace` только для чтения; другие пользовательские каталоги хоста не должны монтироваться. Permission profile ДОЛЖЕН (MUST) запрещать чтение всего filesystem через `:root = "deny"`, затем разрешать только чтение workspace и минимальных runtime-путей; `.env`, сеть команд и hosted web search запрещены. Системный `requirements.toml` внутри образа ДОЛЖЕН (MUST) разрешать `red-alert-harness` через `allowed_permission_profiles`. Codex не должен запрашивать расширение прав или сохранять rollout сессии. Контейнер не должен наследовать переменные OpenAI/Codex с хоста; штатный auth-файл Codex передаётся как временная копия и удаляется после запуска.

#### Scenario: Каталог стенда монтируется только для чтения

- **WHEN** пользователь выполняет `red-alert inspect <path> --analyzer harness`
- **THEN** argv `docker run` содержит bind mount абсолютного `<path>` в `/workspace` с `readonly`, рабочий каталог равен `/workspace`, других пользовательских каталогов хоста в mount нет

#### Scenario: Харнес получает защищённые флаги

- **WHEN** выбран `--analyzer harness`
- **THEN** команда Codex внутри контейнера содержит `--ignore-user-config --profile red-alert-harness --strict-config --ephemeral`, но не содержит `--sandbox` и `--add-dir`

#### Scenario: Профиль запрещает секреты и сеть

- **WHEN** загружается `red-alert-harness.config.toml`
- **THEN** `:root` имеет `deny`, workspace доступен только для чтения, `.env` имеют `deny`, а command network и web search выключены

#### Scenario: Системная политика образа включает custom profile

- **WHEN** собирается поставляемый Docker-образ harness
- **THEN** `/etc/codex/requirements.toml` разрешает `red-alert-harness` и стандартные профили, а config profile находится в `CODEX_HOME` пользователя контейнера

#### Scenario: Родительское окружение не расширяет права харнеса

- **WHEN** Red Alert запущен с `OPENAI_API_KEY`, `CODEX_SANDBOX`, `CODEX_PERMISSION_PROFILE` и `CODEX_SESSION_ID`
- **THEN** `docker run` не передаёт эти переменные в контейнер, а для авторизации использует только временную копию штатного `auth.json`

#### Scenario: Docker недоступен

- **WHEN** выбран `--analyzer harness`, но Docker CLI или daemon недоступен
- **THEN** система не пишет профиль, сообщает понятную ошибку Docker и завершается с кодом 1

### Requirement: Живой анализатор заполняет слоты техник

СИСТЕМА ДОЛЖНА (MUST) передавать `llm` и `harness` краткий каталог шаблонов (`name`, `requires`, `slots`). Для техник, чьи capability не `absent`, анализатор заполняет все слоты конкретными значениями из исходников (домен, объекты данных, критерий успеха). Пустые bindings допустимы только если в коде нет, чем заполнить слот.

#### Scenario: Промпт содержит каталог техник

- **WHEN** собирается задание для llm или harness
- **THEN** в тексте есть имя `memory-poisoning` и слоты `policy`, `trigger`, `proof`

#### Scenario: JSON профиля вытаскивается из шумного вывода

- **WHEN** анализатор вернул лог и JSON-объект StandProfile с bindings
- **THEN** система загружает этот объект и сохраняет заполненные слоты

### Requirement: Исходники не тащат секреты в профиль

СИСТЕМА ДОЛЖНА (MUST) не класть в профиль значения из `.env`, ключи API и содержимое каталогов `.git`, `node_modules`, `.venv`, `__pycache__`. Анализатор не читает эти пути как содержимое для bindings.

#### Scenario: .env не попадает в YAML

- **WHEN** в корне исходников есть `.env` с ключом `sk-secret-stand`
- **THEN** в записанном профиле нет строки `sk-secret-stand`
