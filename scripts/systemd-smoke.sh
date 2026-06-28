#!/usr/bin/env bash
set -euo pipefail

metrics_url="${PRISM_SYSTEMD_METRICS_URL:-http://127.0.0.1:9090/metrics}"
service="${PRISM_SYSTEMD_SERVICE:-prism-agent.service}"
required="${PRISM_SYSTEMD_SMOKE_REQUIRED:-0}"

skip() {
    echo "$1"
    if [ "${required}" = "1" ]; then
        exit 1
    fi
    exit 0
}

if ! command -v systemd-analyze >/dev/null 2>&1; then
    skip "systemd-analyze is not installed; skipping systemd smoke test"
fi

systemd-analyze verify deploy/systemd/prism-agent.service

if [ "$(uname -s)" != "Linux" ]; then
    skip "live systemd smoke requires Linux; current OS is $(uname -s)"
fi

if ! command -v systemctl >/dev/null 2>&1; then
    skip "systemctl is not installed; skipping live systemd smoke test"
fi

if [ "${PRISM_SYSTEMD_SMOKE_INSTALL:-0}" != "1" ]; then
    skip "PRISM_SYSTEMD_SMOKE_INSTALL is not 1; skipping live systemd install smoke test"
fi

if ! systemctl cat "${service}" >/dev/null 2>&1; then
    echo "${service} is not installed; install the package before live systemd smoke" >&2
    exit 1
fi

cleanup() {
    systemctl stop "${service}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

systemctl daemon-reload
systemctl start "${service}"

for _ in $(seq 1 30); do
    if curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"; then
        break
    fi
    sleep 2
done

curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"
journalctl -u "${service}" -n 100 --no-pager | grep -Ei "systemd|metadata|prometheus|agent"
systemctl restart "${service}"
curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"
systemctl stop "${service}"
