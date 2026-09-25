#!/usr/bin/env bash
set -euo pipefail
LAB=${XM_LAB_ROOT:-/var/tmp/x-manager-debian13-lab/rootfs}
touch "$LAB/.x-manager-test-lab"
for proc in /proc/[0-9]*; do
    if [ "$(cat "$proc/comm" 2>/dev/null)" = systemd ] && [ -f "$proc/root/.x-manager-test-lab" ] && [ "$(stat -Lc '%d:%i' "$proc/root")" = "$(stat -Lc '%d:%i' "$LAB")" ]; then
        exec nsenter --target "${proc##*/}" --mount --pid --net --uts --ipc --root --wd="$proc/root" -- "$@"
    fi
done
echo 'Debian lab systemd not found' >&2
exit 1
