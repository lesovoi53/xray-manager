#!/usr/bin/env bash
# ==============================================================================
# webdav-tunnel-routing.sh — iptables anti-loop routing для webdav-tunnel
#
# Логика:
#   1. Трафик пользователя wdavtunnel (UID процесса webdav-tunnel) по умолчанию
#      REDIRECT-уется в Xray REDIRECT порт (12346) через правило OUTPUT.
#   2. ИСКЛЮЧЕНИЯ (прямой выход): loopback, IP сервера, порт WebDAV самого туннеля,
#      а также WebDAV-хосты внешних провайдеров (Nextcloud/Box/etc).
#   3. При $1=up — правила добавляются, при $1=down — удаляются атомарно.
#
# Автор: x-manager integration layer
# ==============================================================================
set -euo pipefail

CHAIN="WDAV_OUT"
XRAY_REDIRECT_PORT="${XRAY_REDIRECT_PORT:-12346}"
WDAV_USER="wdavtunnel"

# Читаем UID пользователя (если процесс запущен до создания юзера — падаем gracefully)
WDAV_UID=$(id -u "$WDAV_USER" 2>/dev/null || echo "")

# Читаем WebDAV-порт из конфига (только чтобы не зациклиться)
WEBDAV_LISTEN_PORT=""
if [ -f /etc/webdav-tunnel/config.env ]; then
    raw_listen=$(grep -oP '^WEBDAV_LISTEN=\K.*' /etc/webdav-tunnel/config.env | tr -d '"' | head -n 1)
    # Формат: :8443 или 0.0.0.0:8443
    WEBDAV_LISTEN_PORT=$(echo "$raw_listen" | grep -oP ':\K[0-9]+$' || true)
fi

# Сервер IP (используется для исключения ответного трафика к клиентам)
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -n 1 || hostname -I 2>/dev/null | awk '{print $1}' || true)

add_rules() {
    if [ -z "$WDAV_UID" ]; then
        echo "[webdav-tunnel-routing] WARN: user $WDAV_USER not found, skipping iptables setup" >&2
        exit 0
    fi

    # Создаём цепочку (игнорируем ошибку если уже существует)
    iptables -t nat -N "$CHAIN" 2>/dev/null || true
    # Очищаем её на случай повторного вызова
    iptables -t nat -F "$CHAIN" 2>/dev/null || true

    # --- ИСКЛЮЧЕНИЯ: трафик, который должен идти напрямую ---

    # 1. Локальный loopback (127.0.0.x) — WebDAV сам с собой
    iptables -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN

    # 2. IP сервера — не нужно перенаправлять трафик к самому себе
    if [ -n "$SERVER_IP" ]; then
        iptables -t nat -A "$CHAIN" -d "$SERVER_IP/32" -j RETURN
    fi

    # 3. Порт WebDAV самого туннеля (selfhosted — к нему обращается relay внутри)
    if [ -n "$WEBDAV_LISTEN_PORT" ]; then
        iptables -t nat -A "$CHAIN" -p tcp --dport "$WEBDAV_LISTEN_PORT" -j RETURN
    fi

    # 4. Уже установленные соединения (ESTABLISHED/RELATED) — не трогаем
    # Применяется через connmark, отдельный ACCEPT в filter уже существует

    # --- РЕДИРЕКТ: остальной TCP → Xray REDIRECT (12346) ---
    # Этот трафик — уже расшифрованный пользовательский TCP,
    # который webdav-tunnel передаёт дальше. Он должен пройти через Xray.
    iptables -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$XRAY_REDIRECT_PORT"

    # Прикрепляем цепочку к OUTPUT только для UID wdavtunnel
    # Проверяем что правило ещё не добавлено
    if ! iptables -t nat -C OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN" 2>/dev/null; then
        iptables -t nat -I OUTPUT 1 -m owner --uid-owner "$WDAV_UID" -j "$CHAIN"
    fi

    echo "[webdav-tunnel-routing] UP: UID=$WDAV_UID → TCP → :$XRAY_REDIRECT_PORT (excl. 127/8, server, :$WEBDAV_LISTEN_PORT)"
}

remove_rules() {
    if [ -z "$WDAV_UID" ]; then
        exit 0
    fi

    # Удаляем цепочку из OUTPUT
    iptables -t nat -D OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN" 2>/dev/null || true
    # Очищаем и удаляем цепочку
    iptables -t nat -F "$CHAIN" 2>/dev/null || true
    iptables -t nat -X "$CHAIN" 2>/dev/null || true

    echo "[webdav-tunnel-routing] DOWN: правила удалены"
}

case "${1:-up}" in
    up)   add_rules ;;
    down) remove_rules ;;
    *)
        echo "Usage: $0 {up|down}" >&2
        exit 1
        ;;
esac
