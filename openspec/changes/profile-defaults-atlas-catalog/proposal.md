## Why

StandProfile разросся: дублирование endpoint/bearer в каждом binding, нет явного «не применимо к цели», каталог атак не привязан к MITRE ATLAS. `attack` больше не должен молча подставлять invest-stand.

## What Changes

- Top-level `defaults` (`target`/`eval`/`persist`) и наследование в bindings: `inherit: target`, `inherit: defaults`, overlay scalar + merge dict.
- `applicable: false` в binding — техника пропускается без ошибки.
- Имена атак и YAML-файлов: `{AML.Txxxx}_{slug}`; ключ binding = `name`.
- Каталог расширен до 18 техник по OWASP Agentic Top 10 / MITRE ATLAS.
- `make keys` — обёртка над `script/fetch_stand_keys.py`.
- **BREAKING**: `attack` требует `--profile` / `RED_ALERT_PROFILE`; упакованный `profiles/invest-stand.yaml` только для демо/тестов, не default CLI.
