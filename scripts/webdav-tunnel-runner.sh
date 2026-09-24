#!/usr/bin/env bash
# ==============================================================================
# webdav-tunnel-runner.sh — Runner для webdav-tunnel (selfhosted & server modes)
# ==============================================================================
set -e

CONFIG_FILE="/etc/webdav-tunnel/config.env"
if [ -f "$CONFIG_FILE" ]; then
    set -a
    . "$CONFIG_FILE"
    set +a
fi

WEBDAV_MODE="${WEBDAV_MODE:-selfhosted}"
WEBDAV_LOGIN="${WEBDAV_LOGIN:-wdav}"
WEBDAV_PASSWORD="${WEBDAV_PASSWORD:-}"
WEBDAV_ENC="${WEBDAV_ENC:-false}"

if [ -z "$WEBDAV_PASSWORD" ]; then
    echo "[webdav-tunnel] ОШИБКА: Пароль WebDAV не задан в $CONFIG_FILE"
    sleep 5
    exit 1
fi

ARGS=()

if [ "$WEBDAV_MODE" = "server" ] || [ "$WEBDAV_MODE" = "external" ]; then
    WEBDAV_URL="${WEBDAV_URL:-https://webdav.yandex.ru}"
    echo "[webdav-tunnel] Запуск в режиме EXTERNAL RELAY (WebDAV: $WEBDAV_URL, пользователь: $WEBDAV_LOGIN)"
    ARGS=("-mode=server" "-webdav=$WEBDAV_URL" "-login=$WEBDAV_LOGIN" "-password=$WEBDAV_PASSWORD")
else
    WEBDAV_LISTEN="${WEBDAV_LISTEN:-:8443}"
    WEBDAV_STORAGE="${WEBDAV_STORAGE:-/var/lib/webdav-tunnel/data}"
    mkdir -p "$WEBDAV_STORAGE" 2>/dev/null || true
    echo "[webdav-tunnel] Запуск в режиме SELFHOSTED (порт $WEBDAV_LISTEN, пользователь: $WEBDAV_LOGIN)"
    ARGS=("-mode=selfhosted" "-webdav-listen=$WEBDAV_LISTEN" "-webdav-storage=$WEBDAV_STORAGE" "-login=$WEBDAV_LOGIN" "-password=$WEBDAV_PASSWORD")
fi

if [ "$WEBDAV_ENC" = "true" ] || [ "$WEBDAV_ENC" = "1" ]; then
    ARGS+=("-enc")
fi

if [ -n "${WEBDAV_DNS:-}" ]; then
    ARGS+=("-dns=$WEBDAV_DNS")
fi

if [ -n "${WEBDAV_PROXY:-}" ]; then
    ARGS+=("-proxy=$WEBDAV_PROXY")
fi

exec /usr/local/bin/webdav-tunnel "${ARGS[@]}"
