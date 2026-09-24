# TUNA Subscription Server (tuna-subscriptions)

Легковесный, автономный локальный HTTP-сервис подписок для панели TUNA на чистом Python 3.

## 🎯 Назначение и границы

Сервис решает задачу безопасного хранения и выдачи персональных ссылок для клиентов TUNA:
1. Хранит ник пользователя и 5 протокольных ссылок (`csqtt`, `qwdtt`, `snell`, `mieru`, `masterdnsvpn`).
2. Генерирует уникальный криптостойкий URL подписки для каждого пользователя.
3. Отдаёт клиенту или панели подписку в виде Base64-текста со строгим сохранением порядка и неизменности байтов.
4. **Не зависит от внешних библиотек** (Zero Dependencies — работает на стандартной библиотеке Python 3.9+).
5. Не взаимодействует с внутренними механизмами маршрутизации панели, не вмешивается в Xray или Sing-box.

---

## 🏗 Архитектура и стек

* **Среда выполнения:** Python 3 (стандартные библиотеки `http.server`, `sqlite3`, `secrets`, `hashlib`, `base64`, `json`, `uuid`). Никаких сторонних pip-пакетов (полная совместимость с PEP 668 на Debian 12/13).
* **База данных:** SQLite 3 в режиме **WAL** (`PRAGMA journal_mode=WAL`, `synchronous=NORMAL`) для гарантии высокой производительности и отсутствия блокировок при одновременных запросах.
* **Безопасность хранения:** Токены пользователей генерируются через `secrets.token_urlsafe(32)` и сохраняются в БД **исключительно в виде SHA-256 хеша**. Открытый токен возвращается клиенту только один раз при создании или ротации.
* **Неизменность URI:** Ссылки протоколов хранятся и выдаются как непрозрачные строки (*opaque strings*). Символы `+`, пустые хеш-параметры `#`, нестандартные схемы `stormdns://` передаются байт-в-байт без нормализации и URL-декодирования.
* **Логирование:** В логах (`/var/log/tuna-subscriptions/service.log`) токены и тела ссылок полностью маскируются.

---

## 📂 Структура компонентов

```text
tuna-sub-server/
├── tuna-subscriptions.py      # Исполняемый демон сервиса
├── config.toml.example        # Пример конфигурации
├── tuna-subscriptions.service # Systemd юнит с изоляцией
├── install-sub-server.sh      # Скрипт автоматической установки
├── README.md                  # Документация сервиса
└── tests/
    └── test_sub_server.py     # 16 приемочных тестов из ТЗ
```

---

## 🚀 Установка на Debian 12 / 13

Для установки выполните:
```bash
sudo bash tuna-sub-server/install-sub-server.sh
```

Инсталлятор автоматически:
1. Создаст системного пользователя `tuna-sub` без доступа к шеллу.
2. Настроит права доступа к каталогам `/etc/tuna-subscriptions`, `/var/lib/tuna-subscriptions`, `/var/log/tuna-subscriptions`.
3. Скопирует демон в `/usr/local/bin/tuna-subscriptions`.
4. Создаст и запустит системную службу `tuna-subscriptions.service`.

### Управление службой:
```bash
systemctl status tuna-subscriptions
systemctl restart tuna-subscriptions
journalctl -u tuna-subscriptions -f
```

---

## ⚙️ Конфигурация (`/etc/tuna-subscriptions/config.toml`)

```toml
[server]
bind_address = "127.0.0.1"
port = 22217
max_request_body_size = 65536

[database]
path = "/var/lib/tuna-subscriptions/subscriptions.db"

[limits]
max_nickname_length = 64
max_uri_length = 4096
max_users = 1000

[logging]
file = "/var/log/tuna-subscriptions/service.log"
level = "INFO"
```

---

## 📡 Спецификация API

### 1. Выдача подписки клиенту: `GET /sub/<token>`

* **Аутентификация:** По секретному токену в пути URL.
* **Успешный ответ (200 OK):**
  * `Content-Type: text/plain; charset=utf-8`
  * `Cache-Control: private, no-store`
  * `ETag: "<revision>-<hash>"`
  * `Profile-Title: <nickname>`
  * **Тело:** Base64-строка, внутри которой ссылки разделены символом `\n` в строгом порядке:
    1. `csqtt`
    2. `qwdtt`
    3. `snell`
    4. `mieru`
    5. `masterdnsvpn`
* **Кэширование:** Если передан заголовок `If-None-Match` и ETag совпадает — сервис возвращает `304 Not Modified` без тела.
* **Ошибки:**
  * Неверный токен или деактивированный пользователь: `401 Unauthorized` или `404 Not Found`.
  * Если у пользователя не задана ни одна ссылка: `204 No Content`.

---

### 2. Локальное управление (Localhost API)

#### 🔹 Создать пользователя
```bash
curl -X POST http://127.0.0.1:22217/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "nickname": "alex_travel",
    "csqtt_uri": "csqtt://1.2.3.4:443?key=abc+def#CSQTT",
    "qwdtt_uri": "qwdtt://1.2.3.4:8443#",
    "snell_uri": "snell://1.2.3.4:9000?psk=pass&version=5#Snell",
    "mieru_uri": "mieru://1.2.3.4:10000?user=alex#Mieru",
    "masterdnsvpn_uri": "stormdns://1.2.3.4:53?k=val#MasterDNS"
  }'
```
*Ответ (201 Created):*
```json
{
  "id": "c1f7a012-...",
  "nickname": "alex_travel",
  "subscription_token": "u_K7...",
  "subscription_url": "http://127.0.0.1:22217/sub/u_K7...",
  "enabled": true,
  "revision": 1
}
```
*(Внимание: `subscription_token` возвращается только один раз!)*

#### 🔹 Список всех пользователей
```bash
curl -s http://127.0.0.1:22217/api/users | jq .
```

#### 🔹 Просмотр профиля пользователя
```bash
curl -s http://127.0.0.1:22217/api/users/<USER_ID> | jq .
```

#### 🔹 Обновление ссылок или статуса пользователя
```bash
curl -X PUT http://127.0.0.1:22217/api/users/<USER_ID> \
  -H "Content-Type: application/json" \
  -d '{
    "snell_uri": "snell://1.2.3.4:9005?psk=newpass&version=5#Snell-Updated",
    "enabled": true
  }'
```

#### 🔹 Ротация токена подписки
Если ссылка скомпрометирована, старый токен аннулируется мгновенно:
```bash
curl -X POST http://127.0.0.1:22217/api/users/<USER_ID>/rotate-token
```
*Ответ:* возвращает новый `subscription_token` и обновленный `subscription_url`.

#### 🔹 Удаление пользователя
```bash
curl -X DELETE http://127.0.0.1:22217/api/users/<USER_ID>
```

---

### 3. OpenFlux v2 Bundle (Контракт TUNA VPN)

Сервис подписок поддерживает спецификацию **OpenFlux v2** для клиента TUNA VPN:
* **Формат строки:** `openflux-bundle://v2/<Base64URL-NoPadding(UTF8(JSON_payload))>`
* **Включение в подписку:** Бандл v2 добавляется отдельной строкой в общий Base64-ответ `GET /sub/<token>`. Клиент TUNA объединяет группы бандла в **одно общее подключение** с балансировкой (`roundRobin` или `leastPing`).
* **Поддерживаемые транспорты (v2):** Строго `"mailru"`, `"boards"`, `"cupsonline"`. Любые устаревшие/неподдерживаемые транспорты (включая `vyandex`) отклоняются валидатором.
* **Режимы:**
  * `classic`: от 1 до 8 групп, в каждой группе ровно 1 URL.
  * `multistream`: от 1 до 8 групп, в каждой группе от 1 до 4 URL (суммарно до 32 URL на бандл).
* **Кодеки:** `legacy` (OpenFlux standard) или `batched`.
* **Шифрование:** Опциональный `encryption_key` (AES-GCM base64 или строка) на уровне каждой отдельной группы.
* **Синхронизация ETag:** При редактировании группы в каталоге или настроек пользователя автоматически инкрементируется ревизия профиля (`revision`) и инвалидируется `ETag`, гарантируя немедленное получение свежей подписки клиентом.

#### 🔹 Каталог групп: `GET /api/openflux/groups`
Возвращает список всех групп OpenFlux в каталоге сервера:
```json
[
  {
    "id": "mailru-pool-1",
    "name": "Mail.Ru Primary",
    "mode": "classic",
    "transport": "mailru",
    "urls": ["https://cloud.mail.ru/public/abcd/1234"],
    "codec": "legacy",
    "encryption_key": null,
    "source_slot": 1
  }
]
```

#### 🔹 Добавление группы: `POST /api/openflux/groups`
```bash
curl -X POST http://127.0.0.1:22217/api/openflux/groups \
  -H "Content-Type: application/json" \
  -d '{
    "id": "mailru-pool-1",
    "name": "Mail.Ru Primary",
    "mode": "classic",
    "transport": "mailru",
    "urls": ["https://cloud.mail.ru/public/abcd/1234"],
    "codec": "legacy"
  }'
```

#### 🔹 Импорт локальных групп: `POST /api/openflux/import-local`
Безопасно считывает экземпляры `/etc/openflux/instances/*.env` и режим `/etc/openflux/pool.mode` на хосте, отфильтровывает несовместимые транспорты (vyandex) и регистрирует группы в каталоге:
```bash
curl -X POST http://127.0.0.1:22217/api/openflux/import-local
```

#### 🔹 Настройка OpenFlux для пользователя: `GET /api/users/<id>/openflux`
Возвращает конфигурацию бандла пользователя и список выбранных групп:
```json
{
  "user_id": "c1f7a012-...",
  "enabled": true,
  "connection_id": "3f90117a-24ea-4c40-bd20-00d9841f3d32",
  "name": "TUNA Multi-Stream",
  "mode": "multistream",
  "balancer_strategy": "leastPing",
  "revision": 3,
  "selected_group_ids": ["mailru-pool-1", "boards-pool-2"],
  "groups": [...]
}
```

#### 🔹 Обновление настроек OpenFlux: `PUT /api/users/<id>/openflux`
Позволяет включить/отключить публикацию бандла, изменить имя подключения, режим, стратегию балансировки и набор выбранных групп (от 1 до 8):
```bash
curl -X PUT http://127.0.0.1:22217/api/users/<id>/openflux \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "name": "Office OpenFlux Cluster",
    "mode": "classic",
    "balancer_strategy": "roundRobin",
    "group_ids": ["mailru-pool-1"]
  }'
```

---

## 🧪 Тестирование

Сервис сопровождается полным комплектом из 33 автоматических приемочных тестов, проверяющих:
1. Создание пользователя и выдачу ссылок базовых протоколов.
2. Уникальность токенов и изоляцию данных между пользователями.
3. Жесткий порядок протоколов и фильтрацию пустых записей.
4. Валидность Base64 и UTF-8 заголовка `Profile-Title`.
5. Сохранение сырых спецсимволов (`+`, `#`, `stormdns://`).
6. Работу ETag и HTTP 304 Not Modified.
7. Недоступность деактивированных пользователей.
8. Маскирование конфиденциальных данных в логах.
9. Сериализацию и валидацию спецификации OpenFlux v2 Bundle.
10. Строгую отбраковку неподдерживаемых транспортов (например, vyandex).
11. Ограничения режимов classic (1 URL) и multistream (1-4 URL, до 8 групп на бандл).
12. Инвалидацию ETag и ревизии пользователя при изменении групп.
13. Безопасный импорт локальных конфигураций OpenFlux без shell eval.
14. Соответствие синтетическим фикстурам контракта TUNA.

Запуск тестов:
```bash
python3 -m unittest discover -s tuna-sub-server/tests -v
```

---

## 🛡 Безопасность и отказоустойчивость

* **Права процесса:** Служба работает под непривилегированным пользователем `tuna-sub` с `ProtectSystem=strict` и `NoNewPrivileges=true`.
* **Доступ к сети:** Сервис слушает локальный интерфейс (`127.0.0.1`), исключая внешний доступ без reverse proxy (например, Nginx с SSL или локального редиректа панели).
* **Резервное копирование базы:**
  ```bash
  sqlite3 /var/lib/tuna-subscriptions/subscriptions.db ".backup /root/tuna_sub_backup.db"
  ```
