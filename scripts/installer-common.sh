#!/usr/bin/env bash
# Sourced by install.sh; errors are fatal and do not expose command arguments.
xm_die() { printf 'X-Manager: %s\n' "$*" >&2; exit 1; }

xm_check_external_watchdog() {
    python3 "$SCRIPT_DIR/scripts/installer-state.py" watchdog-check
}

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
    local control="$SCRIPT_DIR/scripts/service-control.py"
    [ -f "$control" ] || control=/usr/local/share/x-manager/scripts/service-control.py
    if [ -f "$control" ]; then
        local allowed=0
        python3 "$control" can-start "$1" || allowed=$?
        if [ "$allowed" = 1 ]; then
            echo "Preserving inhibited service: $1"
            return
        fi
        [ "$allowed" = 0 ] || xm_die "Cannot verify service policy: $1"
    fi
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

xm_enable() {
    # Existing installations keep all enablement states, including masks/static.
    if [ -n "${XM_BACKUP:-}" ] && python3 - "$XM_BACKUP/state.json" "$1" <<'PY'
import json, sys
name = sys.argv[2] if sys.argv[2].endswith(('.service','.timer')) else sys.argv[2]+'.service'
previous = json.load(open(sys.argv[1]))['services'].get(name, {})
sys.exit(0 if previous.get('enabled') not in ('not-found', '', None) else 1)
PY
    then
        echo "Preserving autostart policy: $1"
        return
    fi
    local control="$SCRIPT_DIR/scripts/service-control.py" allowed=0
    [ -f "$control" ] || control=/usr/local/share/x-manager/scripts/service-control.py
    if [ -f "$control" ]; then
        python3 "$control" can-enable "$1" || allowed=$?
        [ "$allowed" != 1 ] || { echo "Autostart inhibited: $1"; return; }
        [ "$allowed" = 0 ] || xm_die "Cannot verify autostart policy: $1"
    fi
    systemctl enable "$1"
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
    if [[ "$target" = /etc/systemd/system/* ]] && [ -L "$target" ] && [ "$(readlink "$target")" = /dev/null ]; then
        echo "Preserving masked unit: $target"
        return
    fi
    if [[ "$target" = /etc/systemd/system/* ]] && [ -L "/run/systemd/system/${target##*/}" ] && [ "$(readlink "/run/systemd/system/${target##*/}")" = /dev/null ]; then
        echo "Preserving runtime-masked unit: $target"
        return
    fi
    case "$relative" in *.sh|bin/x-manager) bash -n "$SCRIPT_DIR/$relative";; esac
    install -m "$mode" "$SCRIPT_DIR/$relative" "$target.new"
    mv -f "$target.new" "$target"
}

xm_write_unit() {
    local target=$1
    if [ -L "/run/systemd/system/${target##*/}" ] && [ "$(readlink "/run/systemd/system/${target##*/}")" = /dev/null ]; then
        cat >/dev/null
        echo "Preserving runtime-masked unit: $target"
        return
    fi
    if [ -L "$target" ] && [ "$(readlink "$target")" = /dev/null ]; then
        cat >/dev/null
        echo "Preserving masked unit: $target"
        return
    fi
    cat >"$target.new"
    chmod 0644 "$target.new"
    mv -f "$target.new" "$target"
}

xm_begin() {
    XM_BACKUP=$(mktemp -d /var/backups/x-manager-XXXXXXXX)
    chmod 0700 "$XM_BACKUP"
    cp "$SCRIPT_DIR/scripts/installer-state.py" "$XM_BACKUP/installer-state.py"
    python3 "$XM_BACKUP/installer-state.py" backup "$XM_BACKUP" "$SCRIPT_DIR/tuna-sub-server/tuna-subscriptions.py"
    printf 'Backup: %s\n' "$XM_BACKUP"
    # The EXIT trap also resumes a partially paused watchdog on stop failure.
    XM_WATCHDOG_MAINTENANCE=1
    echo 'Обслуживание: временная пауза активных vpn-watchdog.timer/service; автозапуск сохраняется.'
    python3 "$XM_BACKUP/installer-state.py" watchdog-pause "$XM_BACKUP"
    XM_TRANSACTION=1
}

xm_exit() {
    local status=$?
    local rollback_failed=0
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "${XM_TRANSACTION:-0}" = 1 ]; then
        printf 'Installation failed. Restoring backup: %s\n' "$XM_BACKUP" >&2
        if ! python3 "$XM_BACKUP/installer-state.py" restore "$XM_BACKUP"; then
            printf 'ROLLBACK FAILED. Keep backup %s and inspect services before retrying.\n' "$XM_BACKUP" >&2
            rollback_failed=1
        fi
    fi
    if [ "$rollback_failed" = 1 ]; then
        printf 'Watchdog remains paused after rollback failure. Repair the saved backup state, then run install.sh --recover-watchdog.\n' >&2
    elif [ "${XM_WATCHDOG_MAINTENANCE:-0}" = 1 ]; then
        if ! python3 "$XM_BACKUP/installer-state.py" watchdog-resume; then
            printf 'WATCHDOG RESTORE FAILED. Inspect /var/lib/x-manager/maintenance-watchdog.json; run install.sh --recover-watchdog after resolving the conflict.\n' >&2
            status=1
        fi
    fi
    if [ -n "${WORK_DIR:-}" ] && [[ "$WORK_DIR" = /tmp/* ]]; then rm -rf -- "$WORK_DIR"; fi
    exit "$status"
}

xm_finish() {
    XM_TRANSACTION=0
    python3 "$XM_BACKUP/installer-state.py" watchdog-resume
    XM_WATCHDOG_MAINTENANCE=0
    echo 'Обслуживание завершено: исходное активное состояние vpn-watchdog восстановлено.'
}
trap xm_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'printf "Installation failed at line %s (exit %s).\n" "$LINENO" "$?" >&2' ERR
