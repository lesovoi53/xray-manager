#!/usr/bin/env bash
# Sourced by install.sh; errors are fatal and do not expose command arguments.
xm_die() { printf 'X-Manager: %s\n' "$*" >&2; exit 1; }

xm_preflight() {
    [ "$EUID" -eq 0 ] || xm_die 'Run as root.'
    . /etc/os-release
    case "$ID:$VERSION_ID" in
        debian:12|debian:13) ;;
        *) xm_die "Unsupported OS: $ID $VERSION_ID";;
    esac
    case "$(uname -m)" in x86_64) ;; *) xm_die 'Unsupported architecture';; esac
    for cmd in apt-get systemctl flock tar; do command -v "$cmd" >/dev/null || xm_die "Missing prerequisite: $cmd"; done
    [ -d /run/systemd/system ] || xm_die 'A running systemd is required.'
    exec 9>/run/lock/x-manager-install.lock
    flock -n 9 || xm_die 'Another installation or rollback is running.'
}

xm_service() {
    if [ -n "${XM_BACKUP:-}" ] && python3 - "$XM_BACKUP/state.json" "$1" <<'PY'
import json, sys
name = sys.argv[2] if sys.argv[2].endswith('.service') else sys.argv[2]+'.service'
previous = json.load(open(sys.argv[1]))['services'].get(name, {})
sys.exit(0 if previous.get('enabled') not in ('not-found', '', None) and not previous.get('active') else 1)
PY
    then
        echo "Preserving stopped service: $1"
        return
    fi
    systemctl restart "$1"
    sleep 2
    systemctl is-active --quiet "$1" || xm_die "Service failed: $1 (inspect its journal locally)"
    sleep 2
    systemctl is-active --quiet "$1" || xm_die "Service exited after startup: $1"
}

xm_validate_ports() {
    python3 - "$SNELL_PORT" "$MIERU_PORTS" <<'PY'
import sys
snell = int(sys.argv[1])
ports = [int(p) for p in sys.argv[2].split('-')]
for start, end in ((snell, snell), (ports[0], ports[-1])):
    if not 1 <= start <= end <= 65535 or any(start <= p <= end for p in (443, 8443)):
        sys.exit('Invalid or forbidden listener port: no configuration was written')
PY
}

xm_install_asset() {
    local relative=$1 target=$2 mode=$3
    test -s "$SCRIPT_DIR/$relative" || xm_die "Missing distribution file: $relative"
    case "$relative" in *.sh|bin/x-manager) bash -n "$SCRIPT_DIR/$relative";; esac
    install -m "$mode" "$SCRIPT_DIR/$relative" "$target.new"
    mv -f "$target.new" "$target"
}

xm_begin() {
    XM_BACKUP=$(mktemp -d /var/backups/x-manager-XXXXXXXX)
    chmod 0700 "$XM_BACKUP"
    cp "$SCRIPT_DIR/scripts/installer-state.py" "$XM_BACKUP/installer-state.py"
    python3 "$XM_BACKUP/installer-state.py" backup "$XM_BACKUP" "$SCRIPT_DIR/tuna-sub-server/tuna-subscriptions.py"
    XM_TRANSACTION=1
    printf 'Backup: %s\n' "$XM_BACKUP"
}

xm_exit() {
    local status=$?
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "${XM_TRANSACTION:-0}" = 1 ]; then
        printf 'Installation failed. Restoring backup: %s\n' "$XM_BACKUP" >&2
        if ! python3 "$XM_BACKUP/installer-state.py" restore "$XM_BACKUP"; then
            printf 'ROLLBACK FAILED. Keep backup %s and inspect services before retrying.\n' "$XM_BACKUP" >&2
        fi
    fi
    if [ -n "${WORK_DIR:-}" ] && [[ "$WORK_DIR" = /tmp/* ]]; then rm -rf -- "$WORK_DIR"; fi
    exit "$status"
}
trap xm_exit EXIT
trap 'printf "Installation failed at line %s (exit %s).\n" "$LINENO" "$?" >&2' ERR
