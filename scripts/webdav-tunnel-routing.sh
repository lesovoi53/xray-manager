#!/usr/bin/env bash
# ==============================================================================
# webdav-tunnel-routing.sh — iptables anti-loop routing для webdav-tunnel
#
# Логика:
#   1. Проверяет ROUTING_MODE из /etc/webdav-tunnel/config.env.
#   2. Если direct — трафик пользователя wdavtunnel идёт напрямую в WAN.
#   3. Если xray — перенаправляет TCP в Xray REDIRECT порт (12346).
#      Если Xray не запущен/не слушает порт, запуск завершается с ошибкой.
#      Тихий переход на прямой выход запрещён.
#   4. ИСКЛЮЧЕНИЯ: loopback, IP сервера, порт самого WebDAV.
# ==============================================================================
set -euo pipefail
iptables-save >/dev/null

CHAIN="WDAV_OUT"
WDAV_USER="wdavtunnel"
CONFIG_FILE="/etc/webdav-tunnel/config.env"

ROUTING_MODE="xray"
XRAY_REDIRECT_PORT="12346"
WEBDAV_LISTEN_PORT=""

if [ -f "$CONFIG_FILE" ]; then
    rm_val=$(grep -oP '^ROUTING_MODE=\K.*' "$CONFIG_FILE" | tr -d '"' | tr -d "'" | head -n 1 || true)
    [ -n "$rm_val" ] && ROUTING_MODE="$rm_val"

    x_val=$(grep -oP '^XRAY_REDIRECT_PORT=["\x27]?\K[0-9]+' "$CONFIG_FILE" | head -n 1 || true)
    [ -n "$x_val" ] && XRAY_REDIRECT_PORT="$x_val"

    raw_listen=$(grep -oP '^WEBDAV_LISTEN=\K.*' "$CONFIG_FILE" | tr -d '"' | head -n 1 || true)
    WEBDAV_LISTEN_PORT=$(echo "$raw_listen" | grep -oP ':\K[0-9]+$' || true)

    m_val=$(grep -oP '^WEBDAV_MODE=\K.*' "$CONFIG_FILE" | tr -d '"' | tr -d "'" | head -n 1 || true)
    [ -n "$m_val" ] && WEBDAV_MODE="$m_val"

    u_val=$(grep -oP '^WEBDAV_URL=\K.*' "$CONFIG_FILE" | tr -d '"' | tr -d "'" | head -n 1 || true)
    [ -n "$u_val" ] && WEBDAV_URL="$u_val"

    cu_val=$(grep -oP '^MULTI_CUSTOM_URL=\K.*' "$CONFIG_FILE" | tr -d '"' | tr -d "'" | head -n 1 || true)
    [ -n "$cu_val" ] && MULTI_CUSTOM_URL="$cu_val"
fi

WDAV_UID=$(id -u "$WDAV_USER" 2>/dev/null || echo "")
case "$ROUTING_MODE" in direct|xray) ;; *) echo 'Invalid WebDAV routing mode' >&2; exit 1;; esac
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -n 1 || hostname -I 2>/dev/null | awk '{print $1}' || true)

add_rules() {
    if [ -z "$WDAV_UID" ]; then
        exit 0
    fi

    if [ "$ROUTING_MODE" = xray ] && ! ss -H -lnt "sport = :$XRAY_REDIRECT_PORT" | grep -q .; then
        echo "Xray REDIRECT :$XRAY_REDIRECT_PORT is unavailable; refusing a silent direct fallback" >&2
        return 1
    fi

    # Очистка предыдущих правил
while iptables -w 5 -t nat -C OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN" 2>/dev/null; do iptables -w 5 -t nat -D OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN"; done
    if iptables -w 5 -t nat -S "$CHAIN" >/dev/null 2>&1; then iptables -w 5 -t nat -F "$CHAIN"; fi
    if iptables -w 5 -t nat -S "$CHAIN" >/dev/null 2>&1; then iptables -w 5 -t nat -X "$CHAIN"; fi

    if [ "$ROUTING_MODE" = "direct" ]; then
        echo "[webdav-tunnel-routing] UP: Режим direct (прямой выход в WAN, без Xray)"
        return 0
    fi

    iptables -w 5 -t nat -N "$CHAIN"
    if iptables -w 5 -t nat -S "$CHAIN" >/dev/null 2>&1; then iptables -w 5 -t nat -F "$CHAIN"; fi

    # Исключения
    iptables -w 5 -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
    if [ -n "$SERVER_IP" ]; then
        iptables -w 5 -t nat -A "$CHAIN" -d "$SERVER_IP/32" -j RETURN
    fi
    if [ -n "$WEBDAV_LISTEN_PORT" ]; then
        iptables -w 5 -t nat -A "$CHAIN" -p tcp --dport "$WEBDAV_LISTEN_PORT" -j RETURN
    fi

    # Исключения для внешних WebDAV облаков (Яндекс, Mail.ru и др.),
    # чтобы управляющий трафик туннеля к удаленному диску не перенаправлялся в Xray
    # Яндекс IP подсети
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -m multiport --dports 80,443 -d 77.88.0.0/18 -j RETURN
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -m multiport --dports 80,443 -d 87.250.250.0/24 -j RETURN
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -m multiport --dports 80,443 -d 93.158.134.0/24 -j RETURN
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -m multiport --dports 80,443 -d 213.180.193.0/24 -j RETURN

    # Mail.ru / VK IP подсети
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -m multiport --dports 80,443 -d 94.100.180.0/24 -j RETURN
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -m multiport --dports 80,443 -d 217.69.139.0/24 -j RETURN
    iptables -w 5 -t nat -A "$CHAIN" -p tcp -m multiport --dports 80,443 -d 128.140.168.0/21 -j RETURN

    # Разрешение доменных имён внешних WebDAV URL при наличии
    for custom_u in "${WEBDAV_URL:-}" "${MULTI_CUSTOM_URL:-}"; do
        [ -z "$custom_u" ] && continue
        wdav_host=$(echo "$custom_u" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:.*$||')
        if [ -n "$wdav_host" ]; then
            for ip in $(getent ahostsv4 "$wdav_host" | awk '{print $1}' | sort -u); do
    if [ -n "$ip" ]; then iptables -w 5 -t nat -A "$CHAIN" -d "$ip/32" -j RETURN; fi
            done
        fi
    done

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

while iptables -w 5 -t nat -C OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN" 2>/dev/null; do iptables -w 5 -t nat -D OUTPUT -m owner --uid-owner "$WDAV_UID" -j "$CHAIN"; done
    if iptables -w 5 -t nat -S "$CHAIN" >/dev/null 2>&1; then iptables -w 5 -t nat -F "$CHAIN"; fi
    if iptables -w 5 -t nat -S "$CHAIN" >/dev/null 2>&1; then iptables -w 5 -t nat -X "$CHAIN"; fi
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
