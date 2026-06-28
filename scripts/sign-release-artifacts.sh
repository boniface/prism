#!/usr/bin/env bash
set -euo pipefail

dist_dir="${1:-target/dist}"

if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is required to sign release artifacts" >&2
    exit 1
fi

find "${dist_dir}" -maxdepth 1 -type f \
    ! -name '*.bundle' \
    ! -name '*.sig' \
    ! -name '*.pem' \
    -print0 |
    while IFS= read -r -d '' artifact; do
        cosign sign-blob --yes \
            --bundle "${artifact}.bundle" \
            "${artifact}"
    done
