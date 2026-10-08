# Руководство для дальнейшей разработки

Актуальная серверная база: **v2026.10.08.3**. Поддерживаемая платформа — Debian 12/13 amd64 с systemd. Android-клиент разрабатывается отдельно. Это руководство дополняет [пользовательскую документацию](USER_GUIDE.md), [описание Волги](VOLGA_SERVER.md) и [API](../tuna-sub-server/README.md).

## Карта кода

| Задача | Точка входа / реализация |
|---|---|
| Установка и обновление | `install.sh`; общие проверки и транзакция в `scripts/installer-common.sh` |
| Снимок и восстановление | `scripts/installer-state.py`: управляемые пути, SQLite backup, iptables, active/enabled состояния |
| Доставка компонентов | `components.json`, `scripts/release-assets.py`; только конкретный собственный Release и SHA-256 |
| Обновление полного комплекта | `scripts/update-release.sh`: один tag, архив, проверка суммы, установка |
| Терминальный UI | `bin/x-manager`; верхняя навигация `scripts/menu-v2.sh`, карта действий `scripts/menu-actions.tsv` |
| Xray и порты | `scripts/xray-discovery.py`, `detect-gateways.py`, `plan-ports.py`, routing-скрипты |
| OpenFlux runtime | `systemd/openflux@.service`, `scripts/openflux-runner.sh`, `openflux-routing.sh` |
| Волга / cookies | `scripts/openflux-volga.py`, `systemd/volga-cookies.*`, Windows-помощник |
| Ограниченные рестарты | `scripts/tuna-watchdog.py`; постоянного watchdog-процесса нет |
| TUNA HTTP / SQLite / bundles | `tuna-sub-server/tuna-subscriptions.py` |
| Группы автовыбора | `tuna-sub-server/tuna_connection_groups.py` и CLI этого каталога; контракт в `docs/CONNECTION_GROUPS_RC11.md` |
| WebDAV и шифрование | `scripts/webdav-config.py`, `webdav-encryption.py`, runner и каталог TUNA |
| Изменённый OpenFlux core | Release asset `openflux-source.tar.gz`; аудит изменений — `patches/*.patch`, `openflux-provenance.json` |

## Обязательные инварианты

1. Не менять существующие UUID, tokens, ключи, пароли, порты, кодеки и протоколы как побочный эффект обновления. Изменения реквизитов — только отдельное явное действие.
2. Не возвращать отменённые возможности и не подтягивать upstream `latest` автоматически. Источник истины версии — manifest выпуска.
3. Не резервировать новые 443/8443. Подбирать свободные разрешённые порты, сохранять ранее заданные значения; TCP и UDP проверять отдельно.
4. TUNA в согласованной схеме слушает loopback. Публичную подписку выдаёт другой локальный сервис. Не менять код панели для исправления нашего формата.
5. Конфигурация/сборка/загрузка/запуск должны завершаться ошибкой при неудаче. Не маскировать ошибки `|| true`, подавлением stderr или сообщением об успехе.
6. Перед заменой — закрытый снимок. Не ставить в отчёте знак равенства между unit-тестами, тестом в контейнере и проверкой на VPS.
7. Не публиковать `/etc`, SQLite, реальные URI/cookies, SSH-данные, браузерные профили и журналы пользователя. Тестовые fixtures используют искусственные значения.

## Поток подписки и граница клиента

```text
runtime channel -> import local catalog -> user's ordered selected groups
                -> bundle payload -> openflux-bundle://v2/... -> subscription
```

Bundle имеет `schema=tuna.openflux.bundle`, `version=2`, идентификатор, issuer, revision, имя, mode, balancer_strategy и массив groups. У группы — id, name, transport, urls, codec, encryption_key. `vyandex` добавлен к допустимым транспортам без изменения схемы. Ограничения: до восьми выбранных групп, один URL в Classic, до четырёх в Multi-Stream.

Ответ export API содержит метаданные и **вложенный `payload`**. UI обязан читать сведения о bundle из payload, а не подставлять значения по умолчанию из корня ответа. Не считать четыре URL четырьмя группами. Подписка содержит выбранные пользователем группы; импорт каталога сам по себе не выбирает все записи для всех пользователей.

Группы URL-test/Speedtest — отдельная модель, в которой измерения и выбор выполняет клиент после подключения. Сервер хранит настройки, проверяет их и сериализует контракт; не выполняет измерения вместо телефона. JSON и контейнер внутри обычной подписки описаны в [контракте контейнера](GROUP_URI_TRANSPORT_V1.md). Нельзя менять поля клиента, основываясь только на удобстве UI.

Шифрование WebDAV должно согласованно пройти через tunnel config, точно сопоставленные записи каталога, ревизии затронутых пользователей и URI. Общая установка `WEBDAV_ENC=true` не обновляет каталог сама по себе — для этого предназначен существующий synchronizer.

## Как собран OpenFlux

Базовый upstream commit: `d13aa5b701c8ee5311aa638de16c70ea094d9dfd`. Сначала применяется `openflux-multistream.patch`, затем `openflux-volga-server.patch`. Второй патч рассчитан на уже изменённую первым патчем базу. Источником выбранных исправлений Волги служил [PR #115](https://github.com/p1neappleXpress/OpenFlux/pull/115), ревизия `ad516948d881009542ef7a89c01b3b5535bbc9dc`; это не полное включение PR или новой upstream main.

Полный опубликованный source asset уже содержит оба патча. Повторно накладывать их на него нельзя. Он включает Go-модули и тесты, но не vendor-копию всех зависимостей; для чистой сборки нужен доступ к зависимостям либо подготовленный Go-cache. Установка на VPS использует готовые бинарники и не скачивает Go/upstream source.

В этой сборке собственный флаг `--upstream-socks5` охватывает CONNECT и UDP ASSOCIATE. Не заменять его автоматически на одноимённую/похожую upstream опцию: поведение UDP может отличаться. Новые upstream sessions/Noise/автоматический direct fallback не включались. Совместимость старых codec/encryption/multistream должна быть самостоятельным критерием миграции ядра.

Сборка на Linux amd64, Go **1.26.4**:

```bash
export GOTOOLCHAIN=local
bash scripts/build-openflux.sh /tmp/openflux /tmp/openflux-volga-check
```

Скрипт получает source asset по manifest, проверяет хеш, безопасно распаковывает, запускает `go test ./...`, собирает оба бинарника с `CGO_ENABLED=0`. До публикации можно задать `XM_COMPONENT_DIR=/absolute/staged-assets`: хеши проверяются и для локальных файлов.

Из распакованного core дополнительно запускайте:

```bash
go test -race ./transport/yandex ./tunnel ./tunnel/upstream
```

Go-логи не должны содержать URL документов, relay-токены и cookies. Сборочный архив должен содержать только исходники и лицензии, не `.git`, runtime-конфигурации или локальные артефакты.

## Установка как транзакция

Порядок: preflight ОС/архитектуры/systemd → зависимости и план портов → проверенная загрузка компонентов → snapshot → изменения → проверка конфигураций и служб → сохранение полного дистрибутива → commit.

`installer-state.py` — явный allowlist. При добавлении нового бинарника, unit или каталога добавляйте его в snapshot/restore одновременно с установкой. Таймеры имеют суффикс `.timer`, их нельзя автоматически записывать как `.service`. В этом выпуске в откат включены `openflux-volga-check`, `volga-cookies.service` и `.timer`.

Пакеты APT и созданные системные пользователи не удаляются откатом. Новые watchdog drop-in не создаются установщиком: настройка через меню имеет собственную копию. Уже существующие политики сохраняются. Не перезаписывать instance override ради единообразия шаблона.

В ранней тестовой установке может остаться `volga-preview.lock` и старый update-helper, который отказывается обновляться. Для неё выполните полную установку закреплённого выпуска по [инструкции релиза](RELEASE_20260929.md); установщик удаляет маркер только после успешных проверок. Не удалять защиту вручную перед загрузкой неизвестного комплекта.

## Проверки перед изменениями и выпуском

Начните с `git status`, текущей ветки, инструкций репозитория и разницы с опубликованным commit. Не включайте в release чужие незавершённые правки. Для отдельного выпуска допустим чистый checkout и перенос только явно выбранных файлов.

В Linux с Python, bash, jq и `/proc`:

```bash
python3 -m unittest discover -s tests
python3 -m unittest discover -s tuna-sub-server/tests
for script in install.sh bin/x-manager scripts/*.sh; do bash -n "$script" || exit; done
```

Тесты TUNA могут перегенерировать fixtures. Выполняйте в временной копии и проверяйте итоговый diff. Синтаксическая проверка PowerShell не заменяет ручной проход Chrome → captcha → SCP → проверка VPS.

Изолированная приёмка: `tests/prepare-debian-lab.sh`, `lab-boot.sh`, `lab-network.sh`, `lab-enter.sh`. Скрипты `lab-clean-release.py`, `lab-upgrade.py`, `lab-failures.py` и `lab-persistent-rollback.py` запускаются **только** в отдельном systemd/network namespace с маркером `/.x-manager-test-lab`. Их нельзя запускать на рабочем VPS: они намеренно портят конфигурации и восстанавливают снимки.

Матрица: clean, repeat, upgrade с пользователями/токенами/нестандартными портами; отказ зависимости и загрузки; неверный hash; неверный config; отказ реального unit; откат; stopped/disabled состояние; TCP и UDP через реальный SOCKS; bundle roundtrip; ручная приёмка конкретного клиента. Для cookies добавляйте expiry=0/empty, 401, повторный WS, SmartCaptcha/OnlyOffice, отказ проверочного бинарника и сохранение последнего рабочего файла.

## Порядок публикации

1. Соберите и проверьте source/binary assets. Неподменяемые старые компоненты можно перенести только при совпадении SHA-256.
2. Обновите `components.json`, provenance, закреплённый tag bootstrap в `install.sh`, README и release notes. Не заменяйте содержимое уже опубликованного tag.
3. Проверьте staged diff и архив на секреты, локальные пути и runtime-файлы. Сохраните результаты тестов с платформой и ограничениями.
4. Создайте commit, проверьте remote main обоих репозиториев, отправьте fast-forward. При расхождении остановитесь и согласуйте историю без force-push.
5. Создайте draft Release: все manifest assets, `x-manager.tar.gz` из commit и `SHA256SUMS`. Сверьте digest каждого загруженного файла, затем опубликуйте. Оба репозитория должны указывать на один commit и одинаковые assets.
6. Проверьте опубликованный tag/commit и доступность полного комплекта. GitHub-публикация сама по себе не даёт разрешения обновлять остальные VPS.

## Открытые границы

- SmartCaptcha остаётся ручной; её частота определяется Яндексом. Нет гарантии бессрочной работы одного файла cookies.
- Изменения внешнего API возможны; не обещать вечную совместимость закреплённого бинарника.
- Новый Windows-помощник требует отдельной интерактивной приёмки.
- Серверная приёмка Волги не закрывает проблему создания TUN/hev-socks5-tunnel в текущем клиенте. Диагностика и исправление клиента — отдельная задача.
- Watchdog не является мониторингом доступности интернета или качества канала. Поддержка новых unit должна добавляться в явный allowlist с тестом политики.

## Миграция старых установок (v2026.09.29.2)

`xray_gateways.py` объединяет чтение таблицы `inbounds` и `xrayTemplateConfig` для планировщика и мигратора. Не возвращайте два независимых алгоритма выбора портов. Проверки: `tests/test_template_gateway_upgrade.py`. Переход со старого polling watchdog выполняется только при явном `--migrate-legacy-watchdog` и после snapshot. `tests/lab-legacy-watchdog.py` проверяет реальный systemd и оба пути отката. Детали и команда: [инструкция обновления](UPGRADE_TEMPLATE_GATEWAYS.md).

## Snell: URI и связанные подписки

Генератор, привязки, атомарное обновление и тесты описаны в [SNELL_SUBSCRIPTIONS.md](SNELL_SUBSCRIPTIONS.md). Используйте общий helper; не добавляйте отдельный шаблон snell:// в TUI.
