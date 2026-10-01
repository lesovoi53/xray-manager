#!/bin/bash
set -euo pipefail
export XM_PARENT_NET=$(readlink /proc/self/ns/net)
exec unshare --net python3 "$(dirname "$0")/lab-webdav-access.py"
