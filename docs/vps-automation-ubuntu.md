# Автоматизация XRayCheck на VPS (Ubuntu и аналоги)


## 1. Соответствие GitHub Actions и VPS

| Workflow (репозиторий) | Назначение | Аналог на VPS |
|------------------------|------------|---------------|
| `daily-check.yml` | Сбор списков из `links.txt`, SQLite `notworkers`, гео-фильтр RU, локальный `vless_checker` + speedtest, артефакты `configs/available` | Ручной или cron-запуск тех же команд после `git pull`, без push в GitHub |
| `daily-check-docker.yml` | Подготовка входа, `docker compose run` с stdin, iptables по `cidrlist`, объединённая проверка Xray + Hysteria + speedtest, `white-list_available` | Тот же конвейер скриптом оболочки + cron/systemd |
| `mtproto-check.yml` | MTProto из URL и Telegram, отдельные секреты | Опционально: те же `python -m lib.mtproto_checker` при наличии токенов/каналов |
| `speedtest-available.yml`, `notworkers-actualize.yml` и др. | Дополнительные этапы цепочки | По необходимости отдельные таймеры |

На VPS обычно **не нужны** `git push` и base64-кодирование для Pages, если вы только используете файлы локально. Достаточно писать в `configs/` и, при желании, копировать их на другой хост или в бэкап.

---

## 2. Требования к серверу

- **ОС**: Ubuntu 20.04+ (рекомендуется 22.04/24.04 LTS).
- **Ресурсы**: зависят от `MAX_WORKERS` и размера списка; для сценария, близкого к CI, разумно от 2 vCPU и 4 ГБ RAM (больше - быстрее параллельная проверка).
- **Пакеты**: `git`, `curl`, `python3`, `python3-pip`, `python3-venv`, `docker.io` (или Docker CE), `docker-compose-plugin` (команда `docker compose`), `unzip`, `jq` (если будете обновлять `configs/last-updated.json` как в CI).
- **Права Docker**: пользователь в группе `docker` или запуск через `sudo` (см. раздел про безопасность).
- **Сеть**: исходящий HTTPS; для режима с iptables в контейнере образ уже рассчитан на `cap_add: NET_ADMIN` (как в `docker-compose.yml`).

Установка примеров (Ubuntu):

```bash
sudo apt update
sudo apt install -y git curl python3 python3-pip python3-venv unzip jq docker.io docker-compose-plugin
sudo usermod -aG docker "$USER"
# перелогиньтесь, чтобы группа docker применилась
```

---

## 3. Клонирование и однократная настройка

```bash
sudo mkdir -p /opt/xraycheck
sudo chown "$USER:$USER" /opt/xraycheck
cd /opt/xraycheck
git clone https://github.com/WhitePrime/xraycheck.git .
# или ваш форк / зеркало
cp .env.example .env
```

Отредактируйте `.env` под локальный запуск. Для сценария **как Docker workflow** удобно задать значения, совместимые с `docker-compose.yml` (там переопределяются `OUTPUT_FILE=white-list_available`, `CIDR_WHITELIST_FILE=/app/cidrlist`). Полный перечень переменных - в `.env.example` и `README.md`.

Создайте виртуальное окружение Python для хостовых скриптов (фильтры, merge, не внутри контейнера):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Бинарники Xray и Hysteria для **сборки образа** (хост):

```bash
bash tools/setup-binaries.sh
```

При необходимости обновляйте их периодически (в CI вызывается `tools/update-binaries.sh`).

---

## 4. Файл `cidrlist`

В CI список CIDR подгружается с URL из переменной `CIDR_WHITELIST_URL` и сохраняется в корень репозитория как `cidrlist` (первая строка может быть комментарием `# Updated: ...`).

Минимальный ручной апдейт на VPS:

```bash
cd /opt/xraycheck
URL="https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
content=$(curl -sLf --connect-timeout 15 --max-time 60 "$URL") || exit 1
printf '# Updated: %s UTC\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" > cidrlist
printf '%s\n' "$content" >> cidrlist
```

Дальше контейнер читает `/app/cidrlist` при монтировании `.:/app` из `docker-compose.yml`.

---

## 5. Входные данные: `links.txt` и `configs/`

- **Режим merge** (как в `daily-check.yml`): в `links.txt` перечисляются URL списков конфигов (по одному на строку). В `.env` задаётся `MODE=merge` и `LINKS_FILE=links.txt`.
- На хосте перед Docker-этапом CI использует уже подготовленный `configs/available` после локальной проверки и фильтров. На VPS вы можете:
  - либо сначала запускать `python -m lib.vless_checker` в merge-режиме и получать `configs/available`,
  - либо поддерживать `configs/available` своими средствами,
  - либо упростить цепочку и передавать в Docker только готовый список через **stdin** (см. ниже).

Секрет `LINKS_FILE_CONTENT` в GitHub на VPS заменяется обычным файлом `links.txt` с правами `chmod 600`, если в нём чувствительные URL.

---

## 6. Конвейер, близкий к `daily-check-docker.yml`

Ниже - логические шаги (как в workflow). Команды запускайте из корня клона, с активированным `source .venv/bin/activate` и настроенным Docker.

1. **Обновить репозиторий и cidrlist** (по желанию `git pull`).
2. **`tools/setup-binaries.sh`** - если нет `tools/xray` / `tools/hysteria`.
3. **MMDB для `DOCKER_LOCATION_FILTER=RU`**: один раз или при отсутствии файла:
   - `python tools/fetch_dbip_country_lite_mmdb.py configs/dbip-country-lite.mmdb`
4. **Исключения endpoint** (если заданы `EXCLUDE_ENDPOINTS` или файл):
   - `python -m lib.filter_excluded_endpoints configs/available -o configs/available_filt.txt && mv configs/available_filt.txt configs/available`
5. **Отсев под Docker**:
   - не RU: при `FILTER_DOCKER_CONFIGS_ENABLED=true` - `python -m lib.filter_docker_configs configs/available -o ...`
   - RU: шаги `filter_configs_by_cidr_and_geo` как в YAML workflow (длинные команды с `--geo-mmdb`, `--cidr-file cidrlist`).
6. **Merge** `available` + `white-list_available` + опционально `configs/ru` - в workflow это встроенный блок `python -c '...'` (дедуп по `normalize_proxy_link`). Его можно сохранить отдельным скриптом `scripts/merge_docker_input.py` у себя, скопировав логику из workflow.
7. **Финальный сплит по гео/CIDR** перед Docker - снова см. workflow (`filter_configs_by_cidr_and_geo` или `filter_configs_by_location_ip`).
8. **Сборка и запуск контейнера**:
   - `docker compose build`
   - Передать переменные окружения (как в шаге `Run checker in Docker` в YAML): проще экспортировать их из `.env` и добавить нужные `-e` или использовать `env_file` в compose.
   - Запуск со stdin:
     ```bash
     cat configs/available | docker compose run --rm -T \
       --env-file .env \
       -e CIDR_WHITELIST_FILE=/app/cidrlist \
       -e GITHUB_ACTIONS=true \
       vless-checker -
     ```
   Уточните: в CI передаётся длинный список `-e KEY=value`; для паритета скопируйте блок из `.github/workflows/daily-check-docker.yml` в свой `.sh` или используйте `set -a; source .env; set +a` и перечислите только отличия через `-e`.
9. **Права на файлы**: контейнер может создать `configs/white-list_available` от root - выполните `sudo chown "$USER:$(id -gn)" configs/white-list_available "configs/white-list_available(top100)"` при необходимости.
10. **Нормализация комментариев** (как в CI):
    - `python -m lib.strip_vpn_comments configs/white-list_available -o configs/white-list_available`
    - то же для `white-list_available(top100)`.

Шаги 4-7 можно пропустить в упрощённом режиме, если вы **вручную** формируете `configs/available` и сразу передаёте его в пункт 8.

---

## 7. Упрощённый сценарий только Docker

Если нужен только прогон в изоляции с CIDR, без полного merge из CI:

1. Поместите список конфигов в `configs/available` (или подготовьте любой файл).
2. Убедитесь, что в корне есть актуальный `cidrlist`.
3. Выполните:

```bash
source .venv/bin/activate
bash tools/setup-binaries.sh
docker compose build
cat configs/available | docker compose run --rm -T --env-file .env vless-checker -
```

Или задайте `MODE=single` и `DEFAULT_LIST_URL` в `.env` и запустите `docker compose up --build` без stdin (тогда список возьмётся по URL; убедитесь, что это допустимо с точки зрения политики источника).

---

## 8. Локальный daily check без Docker (как `daily-check.yml`)

На хосте (не в контейнере):

```bash
source .venv/bin/activate
export XRAY_PATH="$(pwd)/tools/xray"
export HYSTERIA_PATH="$(pwd)/tools/hysteria"
bash tools/setup-binaries.sh
# MODE=merge, LINKS_FILE=links.txt - в .env или export
python -m lib.vless_checker
```

В репозитории daily check использует SQLite `configs/notworkers.db` и дополнительные шаги слияния; для полного паритета откройте `.github/workflows/daily-check.yml` и перенесите нужные вызовы `python -c` и модулей `notworkers_sqlite` в свой скрипт.

---

## 9. Планировщик: cron

Пример: каждый день в 03:30 по времени сервера:

```bash
crontab -e
```

Строка (пути поправьте):

```text
30 3 * * * /opt/xraycheck/scripts/run-docker-pipeline.sh >> /var/log/xraycheck.log 2>&1
```

Рекомендуется не хранить секреты в аргументах cron; все URL и токены - в `.env` с правами `600`.

---

## 10. Планировщик: systemd timer

Создайте `/etc/systemd/system/xraycheck-docker.service`:

```ini
[Unit]
Description=XRayCheck Docker pipeline
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
User=ВАШ_ПОЛЬЗОВАТЕЛЬ
WorkingDirectory=/opt/xraycheck
ExecStart=/opt/xraycheck/scripts/run-docker-pipeline.sh
```

И таймер `/etc/systemd/system/xraycheck-docker.timer`:

```ini
[Unit]
Description=Daily XRayCheck Docker run

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now xraycheck-docker.timer
sudo systemctl list-timers
```

Скрипт `scripts/run-docker-pipeline.sh` создайте сами, собрав последовательность из раздела 6 (или упростите до раздела 7).

---

## 11. Безопасность и эксплуатация

- Пользователь с доступом к Docker фактически имеет права root на хосте; ограничивайте SSH и используйте отдельного пользователя только для XRayCheck.
- Файлы `links.txt`, `.env`, `configs/notworkers.db` могут содержать чувствительные данные - права `chmod 600`, бэкапы шифруйте.
- Логи не должны печатать полные прокси-ссылки в публичные места без необходимости.
- Обновляйте образ и зависимости: `git pull`, `pip install -r requirements.txt`, `docker compose build --no-cache` по расписанию.

---

## 12. Отладка

- Сухой прогон фильтров: запускайте `python -m lib.filter_excluded_endpoints` и др. с `-h` для справки.
- Если контейнер падает на iptables: проверьте `cap_add: NET_ADMIN` (в compose уже есть) и что не используется урезанный runtime без capabilities.
- Сравните переменные с шагом `Run checker in Docker` в `daily-check-docker.yml` - несовпадение `SPEED_TEST_*` или `STRONG_*` сильно меняет результат.

---

## 13. Где смотреть эталон команд

- Полная последовательность с переменными: `.github/workflows/daily-check-docker.yml`, `.github/workflows/daily-check.yml`.
- Точки входа Python: `lib/docker_entrypoint.py`, `lib/vless_checker.py`, `lib/hysteria_checker.py`, `lib/speedtest_checker.py`.
- Документация переменных окружения: `.env.example`, `README.md`.

При расхождениях поведение определяется **кодом** и актуальными workflow; после обновления репозитория перепроверяйте соответствие своих скриптов новым шагам в YAML.
