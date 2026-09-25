#!/usr/bin/env bash
# This harness refuses to run outside the marked disposable Debian rootfs.
set -uo pipefail
[ -f /.x-manager-test-lab ] || exit 90
snapshot=$(mktemp -d /tmp/x-manager-source-XXXXXXXX)
tar -C /work/x-manager --exclude=.git --exclude=__pycache__ -cf - . | tar -C "$snapshot" -xf -
cd "$snapshot"
if bash install.sh "${1:---direct}" > /tmp/x-manager-install.log 2>&1; then
    tail -25 /tmp/x-manager-install.log
else
    status=$?
    tail -40 /tmp/x-manager-install.log
    exit "$status"
fi
