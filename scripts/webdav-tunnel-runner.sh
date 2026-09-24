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

# Очистка фоновых процессов при выходе
STORAGE_PID=""
RELAY_PID=""
cleanup() {
    [ -n "$STORAGE_PID" ] && kill -TERM "$STORAGE_PID" 2>/dev/null || true
    [ -n "$RELAY_PID" ] && kill -TERM "$RELAY_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [ "$WEBDAV_MODE" = "multi" ]; then
    YAML_FILE="/etc/webdav-tunnel/webdav-tunnel.yaml"
    mkdir -p "/etc/webdav-tunnel" "/var/log/webdav-tunnel" 2>/dev/null || true

    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -n 1 || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    WEBDAV_LISTEN="${WEBDAV_LISTEN:-:8443}"
    WEBDAV_PORT=$(echo "$WEBDAV_LISTEN" | grep -oP ':\K[0-9]+$' || echo "8443")
    WEBDAV_STORAGE="${WEBDAV_STORAGE:-/var/lib/webdav-tunnel/data}"

    # Если включен локальный VPS-сервер в пуле — запускаем storage-only
    if [ "${MULTI_LOCAL_ENABLED:-true}" = "true" ]; then
        mkdir -p "$WEBDAV_STORAGE" 2>/dev/null || true
        echo "[webdav-tunnel] Запуск локального WebDAV Storage (:${WEBDAV_PORT})..."
        /usr/local/bin/webdav-tunnel -mode selfhosted -storage-only \
            -webdav-listen "$WEBDAV_LISTEN" \
            -webdav-storage "$WEBDAV_STORAGE" \
            -login "$WEBDAV_LOGIN" \
            -password "$WEBDAV_PASSWORD" >/var/log/webdav-tunnel/storage.log 2>&1 &
        STORAGE_PID=$!
        sleep 1
    fi

    # Генерация/обновление YAML файла со всеми активными бекендами
    cat > "$YAML_FILE" <<EOF_YAML
mode: server
timeout: 60s
tuning:
  chunk-size: 131071
  coalesce: 10ms
  poll-max: 500ms
  poll-min: 200ms
  puts: 8
  read-max: 8
  read-min: 3
backends:
EOF_YAML

    if [ "${MULTI_LOCAL_ENABLED:-true}" = "true" ]; then
        cat >> "$YAML_FILE" <<EOF_YAML
  - url: http://${SERVER_IP}:${WEBDAV_PORT}
    login: ${WEBDAV_LOGIN}
    password: ${WEBDAV_PASSWORD}
EOF_YAML
    fi

    if [ "${MULTI_MAILRU_ENABLED:-true}" = "true" ] && [ -n "${MULTI_MAILRU_LOGIN:-}" ] && [ -n "${MULTI_MAILRU_PASSWORD:-}" ]; then
        cat >> "$YAML_FILE" <<EOF_YAML
  - url: https://webdav.cloud.mail.ru
    login: ${MULTI_MAILRU_LOGIN}
    password: ${MULTI_MAILRU_PASSWORD}
EOF_YAML
    fi

    if [ "${MULTI_YANDEX_ENABLED:-false}" = "true" ] && [ -n "${MULTI_YANDEX_LOGIN:-}" ] && [ -n "${MULTI_YANDEX_PASSWORD:-}" ]; then
        cat >> "$YAML_FILE" <<EOF_YAML
  - url: https://webdav.yandex.ru
    login: ${MULTI_YANDEX_LOGIN}
    password: ${MULTI_YANDEX_PASSWORD}
EOF_YAML
    fi

    if [ "${MULTI_CUSTOM_ENABLED:-false}" = "true" ] && [ -n "${MULTI_CUSTOM_URL:-}" ] && [ -n "${MULTI_CUSTOM_LOGIN:-}" ] && [ -n "${MULTI_CUSTOM_PASSWORD:-}" ]; then
        cat >> "$YAML_FILE" <<EOF_YAML
  - url: ${MULTI_CUSTOM_URL}
    login: ${MULTI_CUSTOM_LOGIN}
    password: ${MULTI_CUSTOM_PASSWORD}
EOF_YAML
    fi

    if [ "$WEBDAV_ENC" = "true" ] || [ "$WEBDAV_ENC" = "1" ]; then
        echo "enc: true" >> "$YAML_FILE"
    fi

    chmod 640 "$YAML_FILE" 2>/dev/null || true

    echo "[webdav-tunnel] Запуск в режиме MULTI-BACKEND (конфиг: $YAML_FILE)"
    ARGS=("-config=$YAML_FILE")

    if [ "$WEBDAV_ENC" = "true" ] || [ "$WEBDAV_ENC" = "1" ]; then
        ARGS+=("-enc")
    fi
    if [ -n "${WEBDAV_DNS:-}" ]; then
        ARGS+=("-dns=$WEBDAV_DNS")
    fi
    if [ -n "${WEBDAV_PROXY:-}" ]; then
        ARGS+=("-proxy=$WEBDAV_PROXY")
    fi

    /usr/local/bin/webdav-tunnel "${ARGS[@]}" &
    RELAY_PID=$!
    wait "$RELAY_PID"
    exit $?

elif [ "$WEBDAV_MODE" = "server" ] || [ "$WEBDAV_MODE" = "external" ]; then
    WEBDAV_URL="${WEBDAV_URL:-https://webdav.cloud.mail.ru}"
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
