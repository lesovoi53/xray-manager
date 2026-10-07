#!/usr/bin/env bash
# Rebuild the fully patched, hash-checked source distributed in this release.
set -euo pipefail
source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:?Usage: build-openflux.sh OUTPUT [CHECK_OUTPUT]}
check_output=${2:-"${output}-volga-check"}
command -v go >/dev/null
command -v patch >/dev/null
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
# Keep the published upstream source pin; apply the independently reviewed
# fixes strictly, so unexpected source changes fail before compilation.
# Normalize CRLF only in affected files of the verified archive.
sed -i 's/\r$//' "$work/openflux/transport/cupsonline/cupsonline.go" "$work/openflux/transport/yandex/boards.go"
patch --batch --forward --fuzz=0 -p1 -d "$work/openflux" < "$source_dir/patches/openflux-memory.patch"
patch --batch --forward --fuzz=0 -p1 -d "$work/openflux" < "$source_dir/patches/openflux-cupsonline-rooms.patch"
patch --batch --forward --fuzz=0 -p1 -d "$work/openflux" < "$source_dir/patches/openflux-boards-heartbeat.patch"
install -m 0644 "$source_dir/tests/openflux_cupsonline_memory_test.go" "$work/openflux/transport/cupsonline/memory_retention_test.go"
install -m 0644 "$source_dir/tests/openflux_cupsonline_rooms_test.go" "$work/openflux/transport/cupsonline/configured_rooms_test.go"
install -m 0644 "$source_dir/tests/openflux_boards_heartbeat_test.go" "$work/openflux/transport/yandex/boards_heartbeat_test.go"
(
    cd "$work/openflux"
    export CGO_ENABLED=0 GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly
    go test ./...
    go build -trimpath -ldflags='-s -w' -o "$work/openflux-bin" .
    go build -trimpath -ldflags='-s -w' -o "$work/check-bin" ./cmd/volga-check
)
install -m 0755 "$work/openflux-bin" "$output"
install -m 0755 "$work/check-bin" "$check_output"
