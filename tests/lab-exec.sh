#!/usr/bin/env bash
# Execute in the disposable Debian rootfs, with private process/mount namespaces.
# No installer may be run here until a private network and systemd are available.
set -euo pipefail
LAB=/var/tmp/x-manager-debian13-lab/rootfs
SOURCE=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$LAB/work"
exec unshare --mount --pid --fork bash -euo pipefail -c '
    mount --make-rprivate /
    mount -t proc proc "$1/proc"
    mount --rbind /dev "$1/dev"
    mount --bind "$2" "$1/work"
    shift 2
    exec chroot /var/tmp/x-manager-debian13-lab/rootfs "$@"
' bash "$LAB" "$SOURCE" "$@"
