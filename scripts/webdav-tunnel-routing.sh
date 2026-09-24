#!/usr/bin/env bash
# ==============================================================================
# webdav-tunnel-routing.sh — iptables anti-loop routing для webdav-tunnel
#
# Логика:
#   1. Проверяет ROUTING_MODE из /etc/webdav-tunnel/config.env.
#   2. Если direct — трафик пользователя wdavtunnel идёт напрямую в WAN.
#   3. Если xray — перенаправляет TCP в Xray REDIRECT порт (12346).
#      Если Xray не запущен/не слушает порт, правило REDIRECT НЕ активируется,
#      чтобы не сломать доступ в сеть.
#   4. ИСКЛЮЧЕНИЯ: loopback, IP сервера, порт самого WebDAV.
# ==============================================================================
set -euo pipefail

CHAIN="WDAV_OUT"
WDAV_USER="wdavtunnel"
CONFIG_FILE="/etc/webdav-tunnel/config.env"

ROUTING_MODE="xray"
XRAY_REDIRECT_PORT="12346"
WEBDAV_LISTEN_PORT=""

if [ -f "$CONFIG_FILE" ]; then
    rm_val=$(grep -oP '^ROUTING_MODE=\K.*' "$CONFIG_FILE" | tr -d '"' | tr -d "'" | head -n 1 || true)
    [ -n "$rm_val" ] && ROUTING_MODE="$rm_val"

    x_val=$(grep -oP '^XRAY_REDIRECT_PORT=\K[0-9]+' "$CONFIG_FILE" | head -n 1 || true)
    [ -n "$x_val" ] && XRAY_REDIRECT_PORT="$x_val"

    raw_listen=$(grep -oP '^WEBDAV_LISTEN=\K.*' "$CONFIG_FILE" | tr -d '"' | head -n 1 || true)
    WEBDAV_LISTEN_PORT=$(echo "$raw_listen" | grep -oP ':\K[0-9]+$' || true)
fi

WDAV_UID=$(id -u "$WDAV_USER" 2>/dev/null || echo "")
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -n 1 || hostname -I 2>/dev/null | awk '{print $1}' || true)

add_rules() {
    if [ -z "$WDAV_UID" ]; then
        exit 0
    fi

    # Очистка предыдущих правил
    iptables -w 5 -t nat -D OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN" 2>/dev/null || true
    iptables -w 5 -t nat -F "$CHAIN" 2>/dev/null || true
    iptables -w 5 -t nat -X "$CHAIN" 2>/dev/null || true

    if [ "$ROUTING_MODE" = "direct" ]; then
        echo "[webdav-tunnel-routing] UP: Режим direct (прямой выход в WAN, без Xray)"
        return 0
    fi

    # Проверка, слушает ли Xray порт REDIRECT
    if ! ss -tlpn | grep -q ":${XRAY_REDIRECT_PORT} " 2>/dev/null; then
        echo "[webdav-tunnel-routing] ВНИМАНИЕ: Порт Xray REDIRECT (:${XRAY_REDIRECT_PORT}) не прослушивается. Трафик пойдет напрямую (direct)."
        return 0
    fi

    iptables -w 5 -t nat -N "$CHAIN" 2>/dev/null || true
    iptables -w 5 -t nat -F "$CHAIN" 2>/dev/null || true

    # Исключения
    iptables -w 5 -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
    if [ -n "$SERVER_IP" ]; then
        iptables -w 5 -t nat -A "$CHAIN" -d "$SERVER_IP/32" -j RETURN
    fi
    if [ -n "$WEBDAV_LISTEN_PORT" ]; then
        iptables -w 5 -t nat -A "$CHAIN" -p tcp --dport "$WEBDAV_LISTEN_PORT" -j RETURN
    fi

    # Перенаправление в Xray
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$XRAY_REDIRECT_PORT"
    iptables -w 5 -t nat -C OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN" 2>/dev/null || \
        iptables -w 5 -t nat -I OUTPUT 1 -m owner --uid-owner "$WDAV_UID" -j "$CHAIN"

    echo "[webdav-tunnel-routing] UP: UID=$WDAV_UID → TCP → :$XRAY_REDIRECT_PORT"
}

remove_rules() {
    if [ -z "$WDAV_UID" ]; then
        exit 0
    fi

    iptables -w 5 -t nat -D OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN" 2>/dev/null || true
    iptables -w 5 -t nat -F "$CHAIN" 2>/dev/null || true
    iptables -w 5 -t nat -X "$CHAIN" 2>/dev/null || true
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
