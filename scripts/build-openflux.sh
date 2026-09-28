#!/usr/bin/env bash
# Rebuild the fully patched, hash-checked source distributed in this release.
set -euo pipefail
source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:?Usage: build-openflux.sh OUTPUT [CHECK_OUTPUT]}
check_output=${2:-"${output}-volga-check"}
command -v go >/dev/null
[[ $(go env GOVERSION) = go1.26.4 ]] || { echo 'Go 1.26.4 required; use GOTOOLCHAIN=local' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 "$source_dir/scripts/release-assets.py" openflux-source.tar.gz "$work/source.tar.gz"
python3 - "$work" <<'PY'
import pathlib, sys, tarfile
root=pathlib.Path(sys.argv[1])
with tarfile.open(root/'source.tar.gz') as archive:
    for member in archive.getmembers():
        path=pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!='openflux' or not (member.isfile() or member.isdir()):
            sys.exit('Unsafe OpenFlux source archive')
    archive.extractall(root)
PY
(
    cd "$work/openflux"
    export CGO_ENABLED=0 GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly
    go test ./...
    go build -trimpath -ldflags='-s -w' -o "$work/openflux-bin" .
    go build -trimpath -ldflags='-s -w' -o "$work/check-bin" ./cmd/volga-check
)
install -m 0755 "$work/openflux-bin" "$output"
install -m 0755 "$work/check-bin" "$check_output"
