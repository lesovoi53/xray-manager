#!/usr/bin/env bash
# TCP uses REDIRECT; UDP uses policy routing and IP_TRANSPARENT TPROXY.
set -euo pipefail
helper=/usr/local/share/x-manager/scripts/snell-routing.py
if [ ! -f "$helper" ]; then
    helper="$(dirname "$(readlink -f "$0")")/snell-routing.py"
fi
[ -f "$helper" ] || { echo 'Snell routing helper is missing; reinstall the complete distribution.' >&2; exit 1; }
exec python3 "$helper" "$@"
