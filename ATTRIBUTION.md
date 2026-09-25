# Компоненты, авторство и лицензии

Сведения сверены 26 сентября 2026 года для X-Manager **v2026.09.25.2**. Лицензия собственного кода X-Manager — [MIT](LICENSE). Она не заменяет лицензии независимых компонентов. Возможности транспорта, сжатия и шифрования следует относить к их авторам.

## Компоненты закреплённого выпуска

| Компонент | Первоисточник и версия | Материалы лицензии |
|---|---|---|
| Snell | Surge Networks, [официальные примечания](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell), бинарник 5.0.1 | Поставляется оригинальный бинарник; исходников в архиве нет. MIT X-Manager не распространяется на него; условия использования определяются поставщиком |
| Mieru / mita | [enfein/mieru v3.38.0](https://github.com/enfein/mieru/tree/v3.38.0) | GPL-3.0: [mieru.txt](licenses/mieru.txt), [mita.txt](licenses/mita.txt) |
| OpenFlux | [p1neappleXpress/OpenFlux d13aa5b7](https://github.com/p1neappleXpress/OpenFlux/tree/d13aa5b701c8ee5311aa638de16c70ea094d9dfd), с поставляемым патчем | GPL-3.0-or-later по README закреплённой версии; текст GPL-3.0: [openflux.txt](licenses/openflux.txt) |
| WebDAV Tunnel | [spkprsnts/webdav-tunnel b1af4c05](https://github.com/spkprsnts/webdav-tunnel/tree/b1af4c05eb80fd29a6f676be894fa61cd12a3dec), copyright spkprsnts | MIT: [webdav-tunnel.txt](licenses/webdav-tunnel.txt) |
| CottenDNS | [WhiteDNS/CottenDNS v2026.09.01.221444-530ffbf](https://github.com/WhiteDNS/CottenDNS/tree/v2026.09.01.221444-530ffbf) | MIT; цепочка MasterDnsVPN → StormDNS → CottenDNS и уведомления авторов: [cottendns.txt](licenses/cottendns.txt) |
| MasterDnsVPN | [masterking32/MasterDnsVPN v2026.06.13.234407-7de2476](https://github.com/masterking32/MasterDnsVPN/tree/v2026.06.13.234407-7de2476), Amin Mahmoudi | MIT: [masterdns.txt](licenses/masterdns.txt) |
| TUNA Subscription Server | Встроенный модуль [tuna-sub-server](tuna-sub-server) этого репозитория | Лицензия проекта [MIT](LICENSE) |

В собственном Release также размещены соответствующие исходные архивы Mieru, OpenFlux и WebDAV. OpenFlux source asset уже содержит применённый патч; повторное применение не требуется. Состав, происхождение и инструкции для сборки: [licenses/COMPONENTS.md](licenses/COMPONENTS.md). Точные SHA-256: [components.json](components.json).

## Независимые установки и интеграции

Эти бинарники не входят в закреплённую загрузку текущего установщика. Ниже указаны источники изученной документации; они не доказывают версию или условия конкретного ранее установленного бинарника.

| Проект | Роль и первоисточник |
|---|---|
| Xray-core | Внешнее ядро маршрутизации: [XTLS/Xray-core](https://github.com/XTLS/Xray-core). X-Manager использует совместимые локальные шлюзы; не присваивает себе протоколы и криптографию Xray |
| qWDTT | Обслуживание существующей установки. [SpaceNeuroX/proxy-turn-vk-android a296c57](https://github.com/SpaceNeuroX/proxy-turn-vk-android/tree/a296c57eaba69bb9479a24f9157856490890e47d); изученная ревизия содержит GPL-3.0 |
| CSQTT | Обслуживание существующей установки. [amurcanov/csqtt ace2122](https://github.com/amurcanov/csqtt/tree/ace21228f46f056e4a2ba734f2ecb67361d401ad); изученная ревизия содержит PolyForm Noncommercial 1.0.0. Не следует обозначать её как MIT |
| 3X-UI | Необязательная интеграция через поддерживаемую локальную базу. Панель не является обязательным условием standalone Xray и не устанавливается этим комплектом |

Ссылки на существующие сертификаты acme.sh/Let's Encrypt означают поиск локальных файлов. Текущий раздел SSL не устанавливает acme.sh и не реализует собственный ACME-выпуск. AmneziaWG не является устанавливаемым компонентом этого выпуска; его присутствие на конкретном VPS не даёт оснований включать его в перечень возможностей X-Manager.

Документ фиксирует изученные источники и приложенные уведомления, а не выдаёт универсальное заключение о правомерности любого последующего распространения компонентов. Подробное разделение функций оригиналов и интеграции: [сравнение](docs/UPSTREAM_COMPARISON.md).
