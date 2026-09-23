# 📜 Внешние компоненты, авторство и лицензии (Attribution & Licenses)

Проект **X-Manager** объединяет передовые сетевые решения, протоколы обхода блокировок и маршрутизацию трафика через ядро **Xray-core**. Ниже приведён полный перечень всех сторонних компонентов, используемых в проекте, с указанием оригинальных репозиториев, их авторов и юридических лицензий.

---

## 1. Xray-core & AmneziaWG Core (Сетевое ядро маршрутизации)
* **Назначение:** Ядро маршрутизации трафика, протоколы VLESS, XTLS, REALITY, Stream-Up XHTTP, Post-Quantum шифрование (ML-KEM-768), локальные шлюзы TPROXY/REDIRECT/Mixed.
* **Оригинальные репозитории:** 
  * [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
  * [amnezia-vpn/amnezia-core](https://github.com/amnezia-vpn/amnezia-core)
* **Авторы:** XTLS Team (RPRX и сообщество), Amnezia VPN Team
* **Лицензия:** **Mozilla Public License 2.0 (MPL-2.0)** / **GNU General Public License v3.0 (GPL-3.0)**

---

## 2. Mieru / mita (Anti-TSPU Proxy)
* **Назначение:** Сервер обхода ТСПУ с алгоритмами низкой энтропии (Low-Entropy 32/40/48/56-bit), вращением масок (Mask Rotation) и TCP-фрагментацией.
* **Оригинальный репозиторий:** [enfein/mieru](https://github.com/enfein/mieru)
* **Автор:** enfein
* **Лицензия:** **GNU General Public License v3.0 (GPL-3.0)**

---

## 3. Snell v5 (Hybrid 0-RTT Proxy)
* **Назначение:** Высокопроизводительный 0-RTT прокси-протокол (Surge Networks) с гибридным мультиплексированием TCP + UDP/QUIC и HTTP-обфускацией.
* **Официальный источник:** [Surge Networks / dl.nssurge.com](https://dl.nssurge.com/snell/)
* **Автор:** Blankwonder / Surge Networks
* **Лицензия:** **Proprietary Freeware (Серверная часть бесплатна для использования)**

---

## 4. WDTT / qwdtt (proxy-turn-vk-android)
* **Назначение:** VPN-сервер с поддержкой прозрачного TPROXY-перехвата в Xray и туннелирования трафика через белые списки.
* **Оригинальный репозиторий:** [SpaceNeuroX/proxy-turn-vk-android](https://github.com/SpaceNeuroX/proxy-turn-vk-android)
* **Автор:** SpaceNeuroX
* **Лицензия:** **MIT License**

---

## 5. CSQTT (VPN Server)
* **Назначение:** Защищённый туннельный VPN-сервер на базе протокола WireTurn.
* **Оригинальный репозиторий:** [amurcanov/csqtt](https://github.com/amurcanov/csqtt)
* **Автор:** amurcanov
* **Лицензия:** **MIT License**

---

## 6. MasterDnsVPN & CottenDNS (DNS Tunneling)
* **Назначение:** Туннелирование сетевого трафика через DNS-запросы (:53 UDP/TCP) для обхода жестких белых списков.
* **Оригинальные репозитории:** 
  * [masterking32/MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)
  * WhiteDNS / CottenDNS Community
* **Авторы:** masterking32, WhiteDNS contributors
* **Лицензия:** **GPL-3.0 / MIT License**

---

## 7. acme.sh (Автоматизация SSL-сертификатов)
* **Назначение:** Автоматический выпуск и продление SSL/TLS-сертификатов (включая Cloudflare Wildcard *.domain) по протоколам ACME DNS-01 и HTTP-01.
* **Оригинальный репозиторий:** [acmesh-official/acme.sh](https://github.com/acmesh-official/acme.sh)
* **Автор:** Neilpang
* **Лицензия:** **GNU General Public License v3.0 (GPL-3.0)**

---

## 8. TUNA Subscription Server (Сервер подписок)
* **Назначение:** Автономный демон раздачи Base64-подписок с поддержкой нескольких узлов каждого протокола, кастомных имен подключений, защиты токенами SHA-256 и базы SQLite WAL.
* **Компонент:** Встроенный модуль X-Manager (`tuna-subscriptions`)
* **Лицензия:** **MIT License**

---

## ⚖️ Совместимость и соблюдение лицензий

Проект **X-Manager** распространяется под лицензией **MIT License**. Все сторонние модули и бинарные утилиты используются в строгом соответствии с их исходными лицензиями правообладателей (MPL-2.0, GPL-3.0, MIT, Freeware).
