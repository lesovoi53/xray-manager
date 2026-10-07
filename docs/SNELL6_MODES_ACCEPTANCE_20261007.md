# Snell v6: три режима с общим PSK

7 октября 2026: **48/48 проверок прошли**, длительность 68,77 секунды.

Проверен ранее закреплённый Linux amd64 core `1.14.1-extended-2.7.2`, commit
`55faa763f986f4ca8a492d9b2719bc6330d2bef5`, SHA-256 бинарника
`187965235a83a462aa10291cfab561d0caed2fde90a608e6899b17aed9e01ea8`.
Источник и digest release-архива описаны в
[отчёте Debian](SNELL6_DEBIAN_ACCEPTANCE_20261005.md); текущий запуск использует
тот же локальный бинарник, его SHA-256 заново вычислен тестом.

Два процесса ядра работают в локальном Ubuntu WSL, в отдельном network namespace
с единственным поднятым интерфейсом loopback. Все listener используют `127.0.0.1`,
серверное правило также принудительно ограничивает адрес назначения loopback.
Внешняя сеть, VPS, Android и рабочие конфигурации не использовались.

| Сценарий | Проверок | Результат |
|---|---:|---|
| `default`, `unshaped`, `unsafe-raw`, каждый с `reuse=false/true`: HTTPS и UDP echo | 12 | Точный payload доставлен |
| Неверный PSK, `default` и `unshaped`: HTTPS и UDP, оба reuse | 8 | Payload не доставлен |
| Неверный PSK, `unsafe-raw`: HTTPS и UDP, оба reuse | 4 | Payload доставлен: PSK не аутентифицирует этот режим |
| Все шесть направленных несовпадений mode клиента/сервера: HTTPS и UDP, оба reuse | 24 | Payload не доставлен |

HTTPS проверяет сертификат и точное тело 81920 байт. UDP fixture возвращает точный
синтетический payload. Отрицательные проверки дополнительно сверяют счётчики
fixtures: доставленных прикладных запросов нет. Перед каждым запуском выполняется
`core check`. Процессы остановлены, временные конфигурации и TLS-ключ удалены.

`unsafe-raw` передаёт Snell без шифрования и без проверки PSK. Наличие непустого
поля `psk` в конфигурации не означает аутентификацию в этом режиме. HTTPS fixture
защищает собственный payload TLS, но не превращает Snell unsafe-raw в защищённый
туннель. Такое поведение отдельно зафиксировано положительной проверкой с неверным PSK.

Конфигурация сервера: `type=snell`, `version=6`, общий `psk`,
`mode=default|unshaped|unsafe-raw`; `users` и `userkey` отсутствуют.
Клиент задаёт те же `version`, `psk`, `mode` и параметр `reuse`.

Тест: [tests/snell6_modes_acceptance.py](../tests/snell6_modes_acceptance.py).
Машиночитаемый результат: [SNELL6_MODES_RESULTS_20261007.json](SNELL6_MODES_RESULTS_20261007.json).
Журналы сохранены в родительском workspace: `snell6-modes-psk-acceptance-20261007/`.

Команда из корня родительского workspace, внутри локального WSL:

```bash
unshare --net -- bash -euc 'ip link set lo up; python3 x-manager-volga-publish/tests/snell6_modes_acceptance.py --core snell6-linux-lab-20261005/extracted/sing-box-1.14.1-extended-2.7.2-linux-amd64-purego/sing-box --out NEW_RESULTS_DIRECTORY'
```

Нужен Python с `cryptography`; каталог результатов должен быть новым.
Это короткая same-core проверка режимов с общим PSK. Она не проверяет переключение
v5/v6 установщиком, подписки, systemd, Xray, реальный Android, длительный reconnect
или многопользовательскую аутентификацию. Для `reuse` здесь проверены оба значения
настройки; долговечность пула соединений отдельным нагрузочным сценарием не проверялась.
