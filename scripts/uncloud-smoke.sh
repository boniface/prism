#!/usr/bin/env bash
set -euo pipefail

required="${PRISM_UNCLOUD_SMOKE_REQUIRED:-0}"

skip() {
    echo "$1"
    if [ "${required}" = "1" ]; then
        exit 1
    fi
    exit 0
}

grep -qi "Uncloud" docs/platforms/uncloud.md
grep -q "/metrics" docs/platforms/uncloud.md
grep -qi "metadata" docs/platforms/uncloud.md
grep -qi "uninstall" docs/platforms/uncloud.md

if [ "${PRISM_UNCLOUD_SMOKE_LIVE:-0}" != "1" ]; then
    skip "PRISM_UNCLOUD_SMOKE_LIVE is not 1; validated documented Uncloud manual smoke path"
fi

PRISM_SYSTEMD_SMOKE_REQUIRED="${required}" \
    PRISM_SYSTEMD_SMOKE_INSTALL=1 \
    ./scripts/systemd-smoke.sh
