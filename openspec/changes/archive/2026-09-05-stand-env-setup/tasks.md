## 1. Скрипт и разбор параметров

- [x] 1.1 Создать `script/fetch_stand_keys.py` с разбором флагов и переменных (target, Keycloak, realm, client, users, password, env-file); пустой ввод и меньше двух пользователей — код 2 без HTTP.
- [x] 1.2 Собрать список пользователей и имена переменных: первый → `RED_ALERT_API_KEY`, второй → `RED_ALERT_VICTIM_API_KEY`, остальные → `RED_ALERT_USER_<username>_API_KEY`.

## 2. Выпуск ключей и запись .env

- [x] 2.1 Реализовать password grant в Keycloak и `POST /keys` с `X-Forwarded-Access-Token`; вынуть ключ из HTML; сбой HTTP или разбора — код 1.
- [x] 2.2 Реализовать атомарный upsert `.env`: не затирать чужие переменные, копировать `.env.example` если файла нет, писать только после успеха всех пользователей.
- [x] 2.3 Печатать только логины и префикс ключа; сырые ключи, пароли и client secret в вывод не попадают.

## 3. Тесты и документация

- [x] 3.1 Написать автотесты на mock HTTP: успех двух и трёх пользователей, ошибка ввода, сбой второго пользователя не меняет `.env`, секреты скрыты, флаг перекрывает env.
- [x] 3.2 Обновить `.env.example`, `README.md` и `ARCHITECTURE.md`; прогнать pytest, ruff и `openspec validate --change stand-env-setup --strict`.
