#!/usr/bin/env bash
# ==============================================================================
# X-MANAGER: Изолированный раннер инстанса OpenFlux (Канал 1-8)
# ==============================================================================

set -e

export GOMEMLIMIT=${GOMEMLIMIT:-150MiB}
export GODEBUG=${GODEBUG:-madvdontneed=1}

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

# Automatic or manual budgets are numeric data, never shell.
# The service pre-start helper prepares this file before the runner reads it.
if [ -e /etc/openflux/resources.conf ]; then
    [ -r /etc/openflux/resources.conf ] || { echo 'OpenFlux resource budgets are unreadable' >&2; exit 1; }
    RESOURCE_CHANNELS=" "
    RESOURCE_FOUND=0
    while IFS= read -r RESOURCE_LINE || [ -n "$RESOURCE_LINE" ]; do
        case "$RESOURCE_LINE" in ''|'#'*) continue;; esac
        if [[ ! "$RESOURCE_LINE" =~ ^([1-8])=([1-9][0-9]{0,8})MiB$ ]]; then
            echo 'Invalid OpenFlux resource budget; run openflux-resources.py report' >&2
            exit 1
        fi
        RESOURCE_CHANNEL="${BASH_REMATCH[1]}"
        RESOURCE_MIB="${BASH_REMATCH[2]}"
        case "$RESOURCE_CHANNELS" in *" $RESOURCE_CHANNEL "*) echo 'Duplicate OpenFlux resource budget' >&2; exit 1;; esac
        RESOURCE_CHANNELS+="$RESOURCE_CHANNEL "
        if [ "$RESOURCE_CHANNEL" = "$INSTANCE" ]; then
            export GOMEMLIMIT="${RESOURCE_MIB}MiB"
            RESOURCE_FOUND=1
        fi
    done < /etc/openflux/resources.conf
    if [ "$RESOURCE_FOUND" != 1 ]; then
        echo 'No managed OpenFlux memory budget for this channel. Run openflux-resources.py plan and apply with the complete channel list before starting it.' >&2
        exit 1
    fi
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

ARGS=("--role=$ROLE" "--mode=$MODE" "--transport=$TRANSPORT" "--codec=$CODEC")
if [ "$TRANSPORT" = vyandex ]; then
    # Keep document URLs out of the process command line.
    umask 077
    URL_FILE=$(mktemp /etc/openflux/.volga-urls-XXXXXX)
    trap 'rm -f "$URL_FILE"' EXIT
    printf '%s' "$URL" > "$URL_FILE"
    python3 /usr/local/share/x-manager/scripts/openflux-volga.py validate "$URL_FILE"
    # The descriptor remains open across exec; the temporary path is removed.
    exec 3<"$URL_FILE"
    rm "$URL_FILE"
    trap - EXIT
    ARGS+=("--url-file=/proc/self/fd/3")
    COOKIES_FILE="${YANDEX_COOKIES_FILE:-/etc/openflux/yandex-cookies.txt}"
    if [ -e "$COOKIES_FILE" ]; then
        [ -r "$COOKIES_FILE" ] || { echo 'Volga cookies file is unreadable' >&2; exit 1; }
        ARGS+=("--yandex-cookies-file=$COOKIES_FILE")
    elif [ -n "${YANDEX_COOKIES_FILE:-}" ]; then
        echo 'Configured Volga cookies file is missing' >&2; exit 1
    fi
    ROUTING=xray
    [ ! -f /etc/openflux/routing.mode ] || ROUTING=$(tr -d ' \r\n' < /etc/openflux/routing.mode)
    case "$ROUTING" in
        xray)
            [ -r /etc/x-manager/gateways.env ] || { echo 'SOCKS5 gateway configuration missing' >&2; exit 1; }
            . /etc/x-manager/gateways.env
            [[ "${XRAY_SOCKS_PORT:-}" =~ ^[0-9]+$ ]] && ((XRAY_SOCKS_PORT > 0 && XRAY_SOCKS_PORT < 65536)) || { echo 'Invalid SOCKS5 gateway port' >&2; exit 1; }
            ARGS+=("--upstream-socks5=127.0.0.1:$XRAY_SOCKS_PORT")
            ;;
        direct) ;;
        *) echo 'Unknown OpenFlux routing mode' >&2; exit 1;;
    esac
else
    ARGS+=("--url=$URL")
fi

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
    rm -f "$KEY_FILE"
fi

echo "[OpenFlux #$INSTANCE] Запуск: role=$ROLE mode=$MODE transport=$TRANSPORT codec=$CODEC (URL and key hidden)"
exec /usr/local/bin/openflux "${ARGS[@]}"
