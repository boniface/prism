#!/usr/bin/env bash
set -euo pipefail

# Load test profiles for P9-02.
# Measures CPU overhead, RSS, and ring buffer drops under realistic load.
#
# Usage:
#   sudo bash scripts/load-test-profiles.sh
#
# Environment:
#   PRISM_LOAD_PROFILE        cpu|network|exec-storm|mixed (default: mixed)
#   PRISM_LOAD_DURATION_SECONDS  duration per profile (default: 30)
#   PRISM_LOAD_REQUIRED       set to 1 to fail CI on skip (default: 0)
#   PRISM_LOAD_MAX_RSS_KB     RSS bound in KiB (default: 262144 = 256 MiB)
#   PRISM_PROMETHEUS_LISTEN_ADDR  metrics endpoint (default: 127.0.0.1:19093)

profile="${PRISM_LOAD_PROFILE:-mixed}"
duration_seconds="${PRISM_LOAD_DURATION_SECONDS:-30}"
required="${PRISM_LOAD_REQUIRED:-0}"
max_rss_kb="${PRISM_LOAD_MAX_RSS_KB:-262144}"
metrics_addr="${PRISM_PROMETHEUS_LISTEN_ADDR:-127.0.0.1:19093}"
metrics_url="http://${metrics_addr}/metrics"
pin_path="${PRISM_BPF_PIN_PATH:-/sys/fs/bpf/prism-load-test}"
log_dir="${PRISM_LOAD_LOG_DIR:-target/load-test-logs}"
log_file="${log_dir}/load-test-${profile}.log"
results_file="${log_dir}/results-${profile}.txt"
otlp_endpoint="${PRISM_LOAD_OTLP_ENDPOINT:-http://127.0.0.1:4317}"
sample_interval=2
agent_pid=""
load_pid=""
ebpf_object="${PRISM_EBPF_OBJECT:-target/bpfel-unknown-none/release/libprism_ebpf.so}"

mkdir -p "${log_dir}"

skip() {
    echo "$1" | tee "${log_file}"
    if [ "${required}" = "1" ]; then
        exit 1
    fi
    exit 0
}

cleanup() {
    if [ -n "${load_pid}" ] && kill -0 "${load_pid}" >/dev/null 2>&1; then
        kill "${load_pid}" >/dev/null 2>&1 || true
        wait "${load_pid}" >/dev/null 2>&1 || true
    fi
    if [ -n "${agent_pid}" ] && kill -0 "${agent_pid}" >/dev/null 2>&1; then
        kill -INT "${agent_pid}" >/dev/null 2>&1 || true
        wait "${agent_pid}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [ "$(uname -s)" != "Linux" ]; then
    skip "load test requires Linux; current OS is $(uname -s)"
fi

if [ "$(id -u)" -ne 0 ]; then
    skip "load test requires root for eBPF load"
fi

if [ ! -r /sys/kernel/btf/vmlinux ]; then
    skip "load test requires readable /sys/kernel/btf/vmlinux"
fi

if ! mountpoint -q /sys/fs/bpf; then
    skip "load test requires bpffs mounted at /sys/fs/bpf"
fi

if ! command -v curl >/dev/null 2>&1; then
    skip "load test requires curl to scrape /metrics"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

rss_kb() {
    if [ ! -r "/proc/${agent_pid}/status" ]; then
        echo 0
        return
    fi
    awk '/VmRSS:/ { print $2; found=1 } END { if (!found) print 0 }' \
        "/proc/${agent_pid}/status"
}

cpu_percent() {
    if [ -z "${agent_pid}" ]; then
        echo 0
        return
    fi
    ps -p "${agent_pid}" -o %cpu= 2>/dev/null | tr -d ' ' || echo 0
}

wait_for_metrics() {
    for _ in $(seq 1 30); do
        if curl --fail --silent --show-error "${metrics_url}" \
                | grep -q "prism_"; then
            return 0
        fi
        sleep 2
    done
    echo "agent did not expose ${metrics_url}" | tee -a "${log_file}" >&2
    return 1
}

scrape_drops() {
    curl --fail --silent --show-error "${metrics_url}" 2>/dev/null \
        | awk '/prism_cgroup_drops_total/ { sum += $2 } END { print sum+0 }'
}

# ---------------------------------------------------------------------------
# Load generators
# ---------------------------------------------------------------------------

cpu_load() {
    end="$(($(date +%s) + duration_seconds))"
    while [ "$(date +%s)" -lt "${end}" ]; do
        # Spin on arithmetic to generate CPU load.
        i=0
        while [ "${i}" -lt 10000 ]; do
            i=$((i + 1))
        done
    done
}

network_load() {
    end="$(($(date +%s) + duration_seconds))"
    while [ "$(date +%s)" -lt "${end}" ]; do
        curl --silent --max-time 1 http://127.0.0.1 >/dev/null 2>&1 || true
        sleep 0.1 2>/dev/null || sleep 1
    done
}

exec_storm_load() {
    end="$(($(date +%s) + duration_seconds))"
    while [ "$(date +%s)" -lt "${end}" ]; do
        /bin/true
        /bin/ls /proc/self >/dev/null 2>&1 || true
        /bin/echo "" >/dev/null
    done
}

mixed_load() {
    cpu_load &
    network_load &
    exec_storm_load &
    wait
}

# ---------------------------------------------------------------------------
# Start agent
# ---------------------------------------------------------------------------

make build 2>&1 | tee -a "${log_file}"

PRISM_BPF_PIN_PATH="${pin_path}" \
    PRISM_EBPF_OBJECT="${PRISM_EBPF_OBJECT:-target/bpfel-unknown-none/release/libprism_ebpf.so}" \
    PRISM_BPF_EPHEMERAL=true \
    PRISM_PROMETHEUS_LISTEN_ADDR="${metrics_addr}" \
    PRISM_OTLP_ENDPOINT="${otlp_endpoint}" \
    PRISM_CAPTURE_PROCESS_EXEC=true \
    RUST_LOG=info \
    ./target/release/prism-agent >>"${log_file}" 2>&1 &
agent_pid="$!"

wait_for_metrics
echo "agent running pid=${agent_pid} profile=${profile} duration=${duration_seconds}s" \
    | tee -a "${log_file}"

# ---------------------------------------------------------------------------
# Run the selected load profile
# ---------------------------------------------------------------------------

case "${profile}" in
    cpu)
        cpu_load &
        load_pid="$!"
        ;;
    network)
        network_load &
        load_pid="$!"
        ;;
    exec-storm)
        exec_storm_load &
        load_pid="$!"
        ;;
    mixed)
        mixed_load &
        load_pid="$!"
        ;;
    *)
        echo "unknown profile: ${profile}" >&2
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Sample resource usage during the run
# ---------------------------------------------------------------------------

deadline="$(($(date +%s) + duration_seconds))"
peak_rss=0
peak_cpu=0
samples=0

while [ "$(date +%s)" -lt "${deadline}" ]; do
    current_rss="$(rss_kb)"
    current_cpu="$(cpu_percent)"

    if [ "${current_rss}" -gt "${peak_rss}" ]; then
        peak_rss="${current_rss}"
    fi

    # Compare as integers (cpu_percent may be "0.0" — strip decimal)
    current_cpu_int="${current_cpu%%.*}"
    peak_cpu_int="${peak_cpu%%.*}"
    if [ "${current_cpu_int:-0}" -gt "${peak_cpu_int:-0}" ]; then
        peak_cpu="${current_cpu}"
    fi

    if [ "${current_rss}" -gt "${max_rss_kb}" ]; then
        echo "RSS ${current_rss} KiB exceeded bound ${max_rss_kb} KiB" \
            | tee -a "${log_file}" >&2
        exit 1
    fi

    samples=$((samples + 1))
    sleep "${sample_interval}"
done

wait "${load_pid}" >/dev/null 2>&1 || true
load_pid=""

# ---------------------------------------------------------------------------
# Collect final metrics
# ---------------------------------------------------------------------------

final_drops="$(scrape_drops)"
metrics_file="${log_dir}/metrics-final-${profile}.prom"
curl --fail --silent --show-error "${metrics_url}" >"${metrics_file}" || true

# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------

{
    echo "profile=${profile}"
    echo "duration_seconds=${duration_seconds}"
    echo "peak_rss_kb=${peak_rss}"
    echo "peak_cpu_percent=${peak_cpu}"
    echo "ring_buffer_drops=${final_drops}"
    echo "samples=${samples}"
    echo "rss_bound_kb=${max_rss_kb}"
    echo "rss_bound_met=$([ "${peak_rss}" -le "${max_rss_kb}" ] && echo yes || echo no)"
} | tee "${results_file}" | tee -a "${log_file}"

echo "load test completed profile=${profile} peak_rss_kb=${peak_rss} peak_cpu=${peak_cpu}% drops=${final_drops}" \
    | tee -a "${log_file}"
