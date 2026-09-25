#!/usr/bin/env bash
set -euo pipefail
LAB=${XM_LAB_ROOT:-/var/tmp/x-manager-debian13-lab/rootfs}
SOURCE=$(cd "$(dirname "$0")/../.." && pwd)
RUNTIME=/var/tmp/x-manager-debian13-lab/rootfs
export LD_LIBRARY_PATH="$RUNTIME/usr/lib/x86_64-linux-gnu:$RUNTIME/usr/lib/x86_64-linux-gnu/systemd"
exec "$RUNTIME/lib64/ld-linux-x86-64.so.2" --library-path "$LD_LIBRARY_PATH" \
    "$RUNTIME/usr/bin/systemd-nspawn" --directory="$LAB" --boot --register=no \
    --machine=x-manager-lab --private-network --bind="$SOURCE:/work" --console=pipe
