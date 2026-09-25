#!/usr/bin/env bash
# Build the exact source revision compatible with our client and Multi-stream patch.
set -euo pipefail
source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
patch_file=${1:-"$source_dir/patches/openflux-multistream.patch"}
output=${2:?Usage: build-openflux.sh PATCH OUTPUT}
revision=d13aa5b701c8ee5311aa638de16c70ea094d9dfd
test -s "$patch_file" || { echo 'OpenFlux: required patch is missing' >&2; exit 1; }
patch_file=$(realpath "$patch_file")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export GOPATH="${GOPATH:-$work/go}"
export GOCACHE="${GOCACHE:-$work/go-build}"
curl -fL --connect-timeout 15 --max-time 180 --retry 2 \
    "https://codeload.github.com/p1neappleXpress/OpenFlux/tar.gz/$revision" -o "$work/source.tar.gz"
tar -xzf "$work/source.tar.gz" --strip-components=1 -C "$work"
git -C "$work" apply --check "$patch_file"
git -C "$work" apply "$patch_file"
(
    cd "$work"
    export CGO_ENABLED=0 GOTOOLCHAIN=auto
    go test ./transport/... -run 'TestBoardsJSONEnvelope|TestMultiStream|TestFlowHash' -count=1
    go build -trimpath -ldflags='-s -w' -o "$work/openflux" .
)
install -m 0755 "$work/openflux" "$output"
