#!/usr/bin/env bash
# ==============================================================================
# X-MANAGER: Изолированный раннер инстанса OpenFlux (Канал 1-8)
# ==============================================================================

set -e

INSTANCE="${1:-1}"
if [ -n "$INSTANCE" ] && [ -f "/etc/openflux/instances/${INSTANCE}.env" ]; then
    ENV_FILE="/etc/openflux/instances/${INSTANCE}.env"
elif [ -n "$INSTANCE" ] && [ -f "$INSTANCE" ]; then
    ENV_FILE="$INSTANCE"
else
    ENV_FILE="/etc/openflux/openflux.env"
    INSTANCE="1"
fi

if [ -f "$ENV_FILE" ]; then
    set -a
    . "$ENV_FILE"
    set +a
fi

ROLE="${ROLE:-exit}"
MODE="${MODE:-l4}"
TRANSPORT="${TRANSPORT:-vyandex}"
URL="${URL:-}"
CODEC="${CODEC:-legacy}"
DEBUG="${DEBUG:-1}"
ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"
KEY_FILE="/etc/openflux/psk-${INSTANCE}.key"

if [ -z "$URL" ]; then
    echo "[OpenFlux #$INSTANCE] ВНИМАНИЕ: URL не настроен!"
    echo "[OpenFlux #$INSTANCE] Настройте ссылку на документ в $ENV_FILE через x-manager"
    sleep 30
    exit 1
fi

ARGS=("--role=$ROLE" "--mode=$MODE" "--transport=$TRANSPORT" "--codec=$CODEC" "--url=$URL")

if [ "$DEBUG" = "1" ] || [ "$DEBUG" = "true" ]; then
    ARGS+=("--debug")
fi

if [ -n "$ENCRYPTION_KEY" ]; then
    mkdir -p /etc/openflux
    echo -n "$ENCRYPTION_KEY" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    ARGS+=("--encryption-key-file=$KEY_FILE")
elif [ -n "$ENCRYPTION_KEY_FILE" ] && [ -f "$ENCRYPTION_KEY_FILE" ]; then
    ARGS+=("--encryption-key-file=$ENCRYPTION_KEY_FILE")
else
    rm -f "$KEY_FILE" 2>/dev/null || true
fi

echo "[OpenFlux #$INSTANCE] Запуск: /usr/local/bin/openflux ${ARGS[*]}"
exec /usr/local/bin/openflux "${ARGS[@]}"
