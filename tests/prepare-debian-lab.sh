#!/usr/bin/env bash
# Run as root in WSL. Uses only the named disposable /var/tmp lab directory.
set -euo pipefail
LAB=${XM_LAB_DIR:-/var/tmp/x-manager-debian13-lab}
mkdir -p "$LAB/rootfs"
if [ ! -f "$LAB/rootfs/etc/debian_version" ]; then
    python3 - "$LAB" <<'PY'
import json, pathlib, sys, subprocess, base64, os
lab = pathlib.Path(sys.argv[1])
base = 'https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/dist-amd64/' + os.environ.get('XM_DEBIAN_SUITE', 'trixie') + '/oci/'
def get(path):
    return subprocess.check_output(['curl', '-fL', '--retry', '3', '--max-time', '120', base + path])
index = json.loads(get('index.json'))
digest = index['manifests'][0]['digest'].replace(':', '/')
manifest = json.loads(base64.b64decode(index['manifests'][0]['data']))
import hashlib
for i, layer in enumerate(manifest['layers']):
    digest = layer['digest'].split(':')[1]
    data = get('blobs/rootfs.tar.gz')
    assert hashlib.sha256(data).hexdigest() == digest
    (lab / ('layer-%d.tar.gz' % i)).write_bytes(data)
PY
    for layer in "$LAB"/layer-*.tar.gz; do tar -xf "$layer" -C "$LAB/rootfs"; done
fi
cp /etc/resolv.conf "$LAB/rootfs/etc/resolv.conf"
unshare --mount --fork bash -euo pipefail -c '
    mount --make-rprivate /
    mount -t proc proc "$1/proc"
    mount --rbind /dev "$1/dev"
    chroot "$1" /bin/bash -euc "apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv systemd-container curl jq python3 iproute2 iptables unzip openssl qrencode wget ca-certificates"
' bash "$LAB/rootfs"
printf 'LAB_READY=%s\n' "$LAB"
