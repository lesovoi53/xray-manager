#!/usr/bin/env bash
# Full distributions only. Never execute a mixture of files from main/upstream.
set -euo pipefail
[ "$EUID" = 0 ] || { echo 'Run as root' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
base=https://github.com/lesovoi53/xray-manager/releases
fetch() { curl -fL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 --retry 2 "$1" -o "$2"; }
if [ -n "${1:-}" ]; then
    [[ "$1" =~ ^v[0-9][A-Za-z0-9._-]*$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
    base="$base/download/$1"
else
    # Resolve latest once, then pin both downloads to the returned release tag.
    fetch https://api.github.com/repos/lesovoi53/xray-manager/releases/latest "$work/release.json"
    tag=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])' "$work/release.json")
    [[ "$tag" =~ ^v[0-9][A-Za-z0-9._-]*$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
    base="$base/download/$tag"
fi
fetch "$base/x-manager.tar.gz" "$work/x-manager.tar.gz"
fetch "$base/SHA256SUMS" "$work/SHA256SUMS"
python3 - "$work" <<'PY'
import hashlib, pathlib, re, sys, tarfile
root = pathlib.Path(sys.argv[1])
entries = dict((name.lstrip('*'), sha) for sha, name in
               (line.split(None, 1) for line in (root/'SHA256SUMS').read_text().splitlines()))
expected = entries['x-manager.tar.gz']
if not re.fullmatch('[a-f0-9]{64}', expected) or hashlib.sha256((root/'x-manager.tar.gz').read_bytes()).hexdigest() != expected:
    sys.exit('Release SHA-256 mismatch; nothing installed')
with tarfile.open(root/'x-manager.tar.gz') as archive:
    for member in archive.getmembers():
        p = pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or not (member.isfile() or member.isdir()):
            sys.exit('Unsafe release archive')
    archive.extractall(root/'source')
PY
bash "$work/source/install.sh" --update
echo 'Полный выпуск установлен и проверен.'
