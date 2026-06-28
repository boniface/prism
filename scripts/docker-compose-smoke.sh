#!/usr/bin/env bash
set -euo pipefail

compose_file="deploy/docker-compose.yaml"
service="prism-agent"
metrics_url="http://127.0.0.1:9090/metrics"
pin_path="/sys/fs/bpf/prism"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed; skipping Docker Compose smoke test"
    exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "docker compose is not available; skipping Docker Compose smoke test"
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is not available; skipping Docker Compose smoke test"
    exit 0
fi

cleanup() {
    docker compose -f "${compose_file}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -f "${compose_file}" up -d --build "${service}"

for _ in $(seq 1 30); do
    if curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"; then
        break
    fi
    sleep 2
done

curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"
docker compose -f "${compose_file}" logs --no-color "${service}" | grep -Ei "docker|metadata|security|prometheus|agent"

docker compose -f "${compose_file}" down --remove-orphans

if [ -d "${pin_path}" ] && find "${pin_path}" -mindepth 1 -print -quit | grep -q .; then
    echo "stale Prism-owned BPF pins remain under ${pin_path}" >&2
    exit 1
fi
