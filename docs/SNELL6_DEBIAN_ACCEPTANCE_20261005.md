# Snell v6 default: Debian 12 и 13 amd64

Локальная проверка от 5 октября 2026: **64/64 сетевых проверки прошли**, по 32 на каждой системе.

## Закреплённая сборка

- [Выпуск sing-box-extended v1.14.1-extended-2.7.2](https://github.com/shtorm-7/sing-box-extended/releases/tag/v1.14.1-extended-2.7.2).
- Артефакт: `sing-box-1.14.1-extended-2.7.2-linux-amd64-purego.tar.gz`.
- SHA-256 архива: `e4606cc7e3ee19885b5c16ad4ec8e28c8b3bacbc31949f93018cd5c77883b28b`. Совпал с digest GitHub release asset; повторно проверен перед распаковкой в Linux.
- SHA-256 бинарника: `187965235a83a462aa10291cfab561d0caed2fde90a608e6899b17aed9e01ea8`.
- GitHub tag и вывод `version` бинарника указывают на commit `55faa763f986f4ca8a492d9b2719bc6330d2bef5`.
- Бинарник сообщает `go1.27.0-X:nodwarf5 linux/amd64`, CGO disabled. `file` определяет ELF x86-64 с интерпретатором `/lib64/ld-linux-x86-64.so.2`; название purego не является доказательством полностью статической сборки.

Это upstream release, не новая сборка из исходников и не Hydracore. Наличие commit в метаданных и проверенного digest не заменяет воспроизводимую сборку. Клиентские overlays TUNA сюда не добавлялись. Тест использует два процесса этого Linux-бинарника: Snell client и Snell server. Связка Windows/Android TUNA → Linux данным запуском не проверена.

## Среда и результаты

Debian rootfs 12 bookworm и 13 trixie запускались в локальном WSL с отдельными mount/PID/network namespaces. Сеть содержит только loopback; внешняя сеть и VPS не использовались. Это Debian userspace под ядром WSL, не загрузка Debian с собственным ядром и systemd.

| Проверка | Debian 12 | Debian 13 |
|---|---:|---:|
| HTTPS по IPv4, точное тело 81920 байт и проверка TLS-сертификата | 6/6 | 6/6 |
| HTTPS с доменным SOCKS-назначением и SNI | 6/6 | 6/6 |
| UDP DNS A | 6/6 | 6/6 |
| UDP DNS AAAA | 6/6 | 6/6 |
| STUN Binding с проверкой transaction ID и XOR-MAPPED-ADDRESS | 6/6 | 6/6 |
| Неверный PSK не позволяет выполнить HTTPS | 2/2 | 2/2 |
| Итого | **32/32** | **32/32** |
| Продолжительность серии | 3,61 с | 3,60 с |

Режим `default`, PSK-only, для каждого `reuse=false/true` выполнены три серии. Перед запуском каждого процесса проверялась нативная конфигурация. Эти проверки конфигурации отдельно в 64 сетевых результата не включены. Все дочерние ядра завершены. Временные TLS-ключи удалены с хоста и из обоих rootfs.

DNS и STUN обслуживают контролируемые локальные fixtures. Доменное HTTPS-назначение заменяется серверным правилом на loopback с сохранением порта; внешнее разрешение DNS этим не проверяется. Ответ AAAA подтверждает передачу DNS-пакета, не IPv6-транспорт. Короткая серия не подтверждает устойчивость после длительного idle/reconnect.

## Воспроизведение и материалы

Тест: [tests/snell6_local_acceptance.py](../tests/snell6_local_acceptance.py). Для Debian добавлен параметр `--tls-fixture`: временные cert.pem/key.pem создаются заранее, поэтому установка Python cryptography в rootfs не требуется.

Команда внутри каждого изолированного rootfs:

```bash
python3 /opt/snell6-qualification-20261005/test.py \
  --core /opt/snell6-qualification-20261005/sing-box \
  --out /opt/snell6-qualification-20261005/results \
  --tls-fixture /opt/snell6-qualification-20261005/tls
```

`--out` должен быть новым каталогом. Машиночитаемые результаты: [Debian 12](SNELL6_DEBIAN12_RESULTS_20261005.json), [Debian 13](SNELL6_DEBIAN13_RESULTS_20261005.json). Локальная обвязка, архив, бинарник и журналы сохранены в `snell6-linux-lab-20261005/` родительского workspace. Обвязка создаёт отдельную сеть перед chroot; запуск её без изоляции не является эквивалентным тестом.

## Вывод и границы

Кандидат Linux amd64 успешно запускает Snell v6 default и передаёт TCP/HTTPS и обычный UDP relay в Debian 12/13 userspace. Для этого ограниченного сценария различий между двумя системами не обнаружено.

Следующие этапы остаются отдельными: конкретный Android APK против этого сервера, TCP/UDP через существующий Xray gateway, systemd, установка/обновление/откат, длительность и reconnect, userkey, другие v6 modes, QUIC Proxy. Установщик не изменён; новые бинарники в выпуск проекта не добавлены; публикации и подключения к VPS не выполнялись.
