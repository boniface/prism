#!/usr/bin/env bash
set -euo pipefail

run() {
    echo "==> $*"
    "$@"
}

run make docker-smoke
run make helm-smoke
run make package-smoke
run ./scripts/systemd-smoke.sh
run ./scripts/uncloud-smoke.sh
