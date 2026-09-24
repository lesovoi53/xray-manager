#!/usr/bin/env bash
# ==============================================================================
# webdav-tunnel-runner.sh — Runner для webdav-tunnel (selfhosted mode)
# ==============================================================================
set -e

CONFIG_FILE="/etc/webdav-tunnel/config.env"
if [ -f "$CONFIG_FILE" ]; then
    set -a
    . "$CONFIG_FILE"
    set +a
fi

WEBDAV_LISTEN="${WEBDAV_LISTEN:-:8443}"
WEBDAV_STORAGE="${WEBDAV_STORAGE:-/var/lib/webdav-tunnel/data}"
WEBDAV_LOGIN="${WEBDAV_LOGIN:-wdav}"
WEBDAV_PASSWORD="${WEBDAV_PASSWORD:-}"
WEBDAV_ENC="${WEBDAV_ENC:-false}"

if [ -z "$WEBDAV_PASSWORD" ]; then
    echo "[webdav-tunnel] ОШИБКА: Пароль WebDAV не задан в $CONFIG_FILE"
    sleep 5
    exit 1
fi

ARGS=("-mode=selfhosted" "-webdav-listen=$WEBDAV_LISTEN" "-webdav-storage=$WEBDAV_STORAGE" "-login=$WEBDAV_LOGIN" "-password=$WEBDAV_PASSWORD")

if [ "$WEBDAV_ENC" = "true" ] || [ "$WEBDAV_ENC" = "1" ]; then
    ARGS+=("-enc")
fi

exec /usr/local/bin/webdav-tunnel "${ARGS[@]}"
