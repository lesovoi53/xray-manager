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
WEBDAV_ENC="${WEBDAV_ENC:-false}"
WEBDAV_STORAGE="${WEBDAV_STORAGE:-/var/lib/webdav-tunnel/data}"

# Раздельные учетные данные по провайдерам (с обратной совместимостью)
SELFHOSTED_LOGIN="${SELFHOSTED_LOGIN:-wdav}"
SELFHOSTED_PASSWORD="${SELFHOSTED_PASSWORD:-${WEBDAV_PASSWORD:-}}"
SELFHOSTED_PORT="${SELFHOSTED_PORT:-18080}"
raw_listen="${WEBDAV_LISTEN:-}"
if [ -n "$raw_listen" ]; then
    p_from_l=$(echo "$raw_listen" | grep -oP ':\K[0-9]+$' || true)
    [ -n "$p_from_l" ] && SELFHOSTED_PORT="$p_from_l"
fi

if [ "$SELFHOSTED_PORT" = 443 ] || [ "$SELFHOSTED_PORT" = 8443 ]; then
    echo '[webdav-tunnel] Local ports 443 and 8443 are forbidden; migrate the saved configuration explicitly.' >&2
    exit 1
fi

MAILRU_LOGIN="${MAILRU_LOGIN:-${MULTI_MAILRU_LOGIN:-}}"
MAILRU_PASSWORD="${MAILRU_PASSWORD:-${MULTI_MAILRU_PASSWORD:-}}"

YANDEX_LOGIN="${YANDEX_LOGIN:-${MULTI_YANDEX_LOGIN:-}}"
YANDEX_PASSWORD="${YANDEX_PASSWORD:-${MULTI_YANDEX_PASSWORD:-}}"

CUSTOM_URL="${CUSTOM_URL:-${MULTI_CUSTOM_URL:-}}"
CUSTOM_LOGIN="${CUSTOM_LOGIN:-${MULTI_CUSTOM_LOGIN:-}}"
CUSTOM_PASSWORD="${CUSTOM_PASSWORD:-${MULTI_CUSTOM_PASSWORD:-}}"

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

    # Если включен локальный VPS-сервер в пуле — запускаем storage-only
    if [ "${MULTI_LOCAL_ENABLED:-true}" = "true" ]; then
        if [ -z "$SELFHOSTED_PASSWORD" ]; then
            echo "[webdav-tunnel] ОШИБКА: Пароль для локального сервера VPS не задан"
            sleep 5
            exit 1
        fi
        mkdir -p "$WEBDAV_STORAGE" 2>/dev/null || true
        echo "[webdav-tunnel] Запуск локального WebDAV Storage (:${SELFHOSTED_PORT}, user: ${SELFHOSTED_LOGIN})..."
        /usr/local/bin/webdav-tunnel -mode selfhosted -storage-only \
            -webdav-listen ":${SELFHOSTED_PORT}" \
            -webdav-storage "$WEBDAV_STORAGE" \
            -login "$SELFHOSTED_LOGIN" \
            -password "$SELFHOSTED_PASSWORD" >/var/log/webdav-tunnel/storage.log 2>&1 &
        STORAGE_PID=$!
        sleep 1
    fi

    export SERVER_IP SELFHOSTED_PORT SELFHOSTED_LOGIN SELFHOSTED_PASSWORD
    export MAILRU_LOGIN MAILRU_PASSWORD YANDEX_LOGIN YANDEX_PASSWORD CUSTOM_URL CUSTOM_LOGIN CUSTOM_PASSWORD WEBDAV_ENC
    python3 /usr/local/share/x-manager/scripts/webdav-config.py

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
    if [ -n "$STORAGE_PID" ]; then
        if wait -n "$RELAY_PID" "$STORAGE_PID"; then
            echo '[webdav-tunnel] A required multi-backend process exited unexpectedly' >&2
            exit 1
        else
            exit $?
        fi
    fi
    wait "$RELAY_PID"
    exit $?

elif [ "$WEBDAV_MODE" = "mailru" ] || ( [ "$WEBDAV_MODE" = "server" ] && [[ "${WEBDAV_URL:-}" =~ mail\.ru ]] ); then
    if [ -z "$MAILRU_PASSWORD" ]; then
        echo "[webdav-tunnel] ОШИБКА: Пароль приложения Mail.ru не задан"
        sleep 5
        exit 1
    fi
    echo "[webdav-tunnel] Запуск в режиме MAIL.RU (пользователь: $MAILRU_LOGIN)"
    ARGS=("-mode=server" "-webdav=https://webdav.cloud.mail.ru" "-login=$MAILRU_LOGIN" "-password=$MAILRU_PASSWORD")

elif [ "$WEBDAV_MODE" = "yandex" ] || ( [ "$WEBDAV_MODE" = "server" ] && [[ "${WEBDAV_URL:-}" =~ yandex ]] ); then
    if [ -z "$YANDEX_PASSWORD" ]; then
        echo "[webdav-tunnel] ОШИБКА: Пароль приложения Яндекс не задан"
        sleep 5
        exit 1
    fi
    echo "[webdav-tunnel] Запуск в режиме YANDEX.DISK (пользователь: $YANDEX_LOGIN)"
    ARGS=("-mode=server" "-webdav=https://webdav.yandex.ru" "-login=$YANDEX_LOGIN" "-password=$YANDEX_PASSWORD")

elif [ "$WEBDAV_MODE" = "custom" ] || [ "$WEBDAV_MODE" = "server" ] || [ "$WEBDAV_MODE" = "external" ]; then
    TARGET_URL="${CUSTOM_URL:-${WEBDAV_URL:-https://webdav.cloud.mail.ru}}"
    TARGET_LOGIN="${CUSTOM_LOGIN:-${WEBDAV_LOGIN:-}}"
    TARGET_PASSWORD="${CUSTOM_PASSWORD:-${WEBDAV_PASSWORD:-}}"
    if [ -z "$TARGET_PASSWORD" ]; then
        echo "[webdav-tunnel] ОШИБКА: Пароль WebDAV не задан"
        sleep 5
        exit 1
    fi
    echo "[webdav-tunnel] Запуск в режиме EXTERNAL RELAY ($TARGET_URL, пользователь: $TARGET_LOGIN)"
    ARGS=("-mode=server" "-webdav=$TARGET_URL" "-login=$TARGET_LOGIN" "-password=$TARGET_PASSWORD")

else
    # Selfhosted
    if [ -z "$SELFHOSTED_PASSWORD" ]; then
        echo "[webdav-tunnel] ОШИБКА: Пароль встроенного WebDAV не задан"
        sleep 5
        exit 1
    fi
    mkdir -p "$WEBDAV_STORAGE" 2>/dev/null || true
    echo "[webdav-tunnel] Запуск в режиме SELFHOSTED (порт :${SELFHOSTED_PORT}, пользователь: $SELFHOSTED_LOGIN)"
    ARGS=("-mode=selfhosted" "-webdav-listen=:${SELFHOSTED_PORT}" "-webdav-storage=$WEBDAV_STORAGE" "-login=$SELFHOSTED_LOGIN" "-password=$SELFHOSTED_PASSWORD")
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
