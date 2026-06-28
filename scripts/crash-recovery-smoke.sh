#!/usr/bin/env bash
set -euo pipefail

required="${PRISM_CRASH_RECOVERY_REQUIRED:-0}"
iterations="${PRISM_CRASH_RECOVERY_ITERATIONS:-3}"
startup_seconds="${PRISM_CRASH_STARTUP_SECONDS:-20}"
shutdown_seconds="${PRISM_CRASH_SHUTDOWN_SECONDS:-10}"
pin_path="${PRISM_BPF_PIN_PATH:-/sys/fs/bpf/prism-crash-recovery}"
metrics_addr="${PRISM_PROMETHEUS_LISTEN_ADDR:-127.0.0.1:19090}"
metrics_url="http://${metrics_addr}/metrics"
log_dir="${PRISM_CRASH_LOG_DIR:-target/crash-recovery-logs}"
log_file="${log_dir}/crash-recovery.log"
agent_pid=""

mkdir -p "${log_dir}"

skip() {
    echo "$1" | tee "${log_file}"
    if [ "${required}" = "1" ]; then
        exit 1
    fi
    exit 0
}

cleanup() {
    if [ -n "${agent_pid}" ] && kill -0 "${agent_pid}" >/dev/null 2>&1; then
        kill -INT "${agent_pid}" >/dev/null 2>&1 || true
        wait "${agent_pid}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [ "$(uname -s)" != "Linux" ]; then
    skip "crash recovery smoke requires Linux; current OS is $(uname -s)"
fi

if [ "$(id -u)" -ne 0 ]; then
    skip "crash recovery smoke requires root so SIGKILL and eBPF state use the same privilege boundary"
fi

if [ ! -r /sys/kernel/btf/vmlinux ]; then
    skip "crash recovery smoke requires readable /sys/kernel/btf/vmlinux"
fi

if ! mountpoint -q /sys/fs/bpf; then
    skip "crash recovery smoke requires bpffs mounted at /sys/fs/bpf"
fi

if ! command -v curl >/dev/null 2>&1; then
    skip "crash recovery smoke requires curl to validate /metrics"
fi

mkdir -p "${pin_path}"
make build 2>&1 | tee "${log_file}"

count_prism_pins() {
    if [ ! -d "${pin_path}" ]; then
        echo 0
        return
    fi

    find "${pin_path}" -mindepth 1 -name 'prism-*' -print | wc -l | tr -d ' '
}

wait_for_metrics() {
    for _ in $(seq 1 "${startup_seconds}"); do
        if curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"; then
            return 0
        fi
        sleep 1
    done

    echo "agent did not expose ${metrics_url} within ${startup_seconds}s" | tee -a "${log_file}" >&2
    return 1
}

start_agent() {
    PRISM_BPF_PIN_PATH="${pin_path}" \
        PRISM_BPF_EPHEMERAL=true \
        PRISM_PROMETHEUS_LISTEN_ADDR="${metrics_addr}" \
        PRISM_CAPTURE_PROCESS_EXEC=false \
        ./target/release/prism-agent >>"${log_file}" 2>&1 &
    agent_pid="$!"
    wait_for_metrics
}

kill_agent() {
    kill -KILL "${agent_pid}"
    wait "${agent_pid}" >/dev/null 2>&1 || true
    agent_pid=""
}

reconcile_with_clean_shutdown() {
    set +e
    PRISM_BPF_PIN_PATH="${pin_path}" \
        PRISM_BPF_EPHEMERAL=true \
        PRISM_PROMETHEUS_LISTEN_ADDR="${metrics_addr}" \
        PRISM_CAPTURE_PROCESS_EXEC=false \
        timeout --signal=INT "${shutdown_seconds}" ./target/release/prism-agent >>"${log_file}" 2>&1
    status="$?"
    set -e

    if [ "${status}" -ne 0 ] && [ "${status}" -ne 124 ]; then
        echo "reconciliation restart failed with status ${status}" | tee -a "${log_file}" >&2
        return "${status}"
    fi
}

baseline="$(count_prism_pins)"
echo "baseline Prism-owned pin count: ${baseline}" | tee -a "${log_file}"

for iteration in $(seq 1 "${iterations}"); do
    echo "crash recovery iteration ${iteration}/${iterations}" | tee -a "${log_file}"
    start_agent
    kill_agent
    after_kill="$(count_prism_pins)"
    echo "pin count after SIGKILL: ${after_kill}" | tee -a "${log_file}"
    reconcile_with_clean_shutdown
    after_reconcile="$(count_prism_pins)"
    echo "pin count after restart reconciliation: ${after_reconcile}" | tee -a "${log_file}"

    if [ "${after_reconcile}" -gt "${baseline}" ]; then
        echo "Prism-owned pin count increased from ${baseline} to ${after_reconcile}" | tee -a "${log_file}" >&2
        exit 1
    fi
done
