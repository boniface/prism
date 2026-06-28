#!/usr/bin/env bash
set -euo pipefail

required="${PRISM_CHAOS_REQUIRED:-0}"
profile="${PRISM_SOAK_PROFILE:-smoke}"
duration_seconds="${PRISM_SOAK_DURATION_SECONDS:-}"
metrics_addr="${PRISM_PROMETHEUS_LISTEN_ADDR:-127.0.0.1:19092}"
metrics_url="http://${metrics_addr}/metrics"
pin_path="${PRISM_BPF_PIN_PATH:-/sys/fs/bpf/prism-chaos-soak}"
log_dir="${PRISM_CHAOS_LOG_DIR:-target/chaos-soak-logs}"
log_file="${log_dir}/chaos-soak.log"
max_rss_kb="${PRISM_SOAK_MAX_RSS_KB:-262144}"
sample_interval_seconds="${PRISM_SOAK_SAMPLE_INTERVAL_SECONDS:-5}"
event_rate_seconds="${PRISM_HIGH_EVENT_RATE_SECONDS:-30}"
otlp_endpoint="${PRISM_CHAOS_OTLP_ENDPOINT:-http://127.0.0.1:4317}"
agent_pid=""
event_pid=""

mkdir -p "${log_dir}"

skip() {
    echo "$1" | tee "${log_file}"
    if [ "${required}" = "1" ]; then
        exit 1
    fi
    exit 0
}

cleanup() {
    if [ -n "${event_pid}" ] && kill -0 "${event_pid}" >/dev/null 2>&1; then
        kill "${event_pid}" >/dev/null 2>&1 || true
        wait "${event_pid}" >/dev/null 2>&1 || true
    fi
    if [ -n "${agent_pid}" ] && kill -0 "${agent_pid}" >/dev/null 2>&1; then
        kill -INT "${agent_pid}" >/dev/null 2>&1 || true
        wait "${agent_pid}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

case "${profile}" in
    smoke)
        duration_seconds="${duration_seconds:-60}"
        ;;
    24h)
        duration_seconds="${duration_seconds:-86400}"
        ;;
    *)
        echo "unknown soak profile: ${profile}" >&2
        exit 1
        ;;
esac

if [ "$(uname -s)" != "Linux" ]; then
    skip "chaos soak requires Linux; current OS is $(uname -s)"
fi

if [ "$(id -u)" -ne 0 ]; then
    skip "chaos soak requires root for eBPF load and process supervision"
fi

if [ ! -r /sys/kernel/btf/vmlinux ]; then
    skip "chaos soak requires readable /sys/kernel/btf/vmlinux"
fi

if ! mountpoint -q /sys/fs/bpf; then
    skip "chaos soak requires bpffs mounted at /sys/fs/bpf"
fi

if ! command -v curl >/dev/null 2>&1; then
    skip "chaos soak requires curl to validate /metrics"
fi

make build 2>&1 | tee "${log_file}"
mkdir -p "${pin_path}"

wait_for_metrics() {
    for _ in $(seq 1 30); do
        if curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"; then
            return 0
        fi
        sleep 2
    done

    echo "agent did not expose ${metrics_url}" | tee -a "${log_file}" >&2
    return 1
}

rss_kb() {
    if [ ! -r "/proc/${agent_pid}/status" ]; then
        echo 0
        return
    fi

    awk '/VmRSS:/ { print $2; found = 1 } END { if (!found) print 0 }' "/proc/${agent_pid}/status"
}

generate_high_event_rate() {
    end_time="$(($(date +%s) + event_rate_seconds))"
    while [ "$(date +%s)" -lt "${end_time}" ]; do
        /bin/true
        /bin/ls /proc/self >/dev/null 2>&1 || true
    done
}

PRISM_BPF_PIN_PATH="${pin_path}" \
    PRISM_BPF_EPHEMERAL=true \
    PRISM_PROMETHEUS_LISTEN_ADDR="${metrics_addr}" \
    PRISM_OTLP_ENDPOINT="${otlp_endpoint}" \
    PRISM_CAPTURE_PROCESS_EXEC=true \
    ./target/release/prism-agent >>"${log_file}" 2>&1 &
agent_pid="$!"

wait_for_metrics
echo "collector outage endpoint configured as ${otlp_endpoint}" | tee -a "${log_file}"

generate_high_event_rate &
event_pid="$!"

deadline="$(($(date +%s) + duration_seconds))"
peak_rss=0

while [ "$(date +%s)" -lt "${deadline}" ]; do
    curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"
    current_rss="$(rss_kb)"
    if [ "${current_rss}" -gt "${peak_rss}" ]; then
        peak_rss="${current_rss}"
    fi
    if [ "${current_rss}" -gt "${max_rss_kb}" ]; then
        echo "agent RSS ${current_rss} KiB exceeded bound ${max_rss_kb} KiB" | tee -a "${log_file}" >&2
        exit 1
    fi
    sleep "${sample_interval_seconds}"
done

wait "${event_pid}" >/dev/null 2>&1 || true
event_pid=""

metrics_file="${log_dir}/metrics-final.prom"
curl --fail --silent --show-error "${metrics_url}" >"${metrics_file}"
grep -q "prism_metric_series_dropped_total" "${metrics_file}"
if grep -q "prism_cgroup_" "${metrics_file}"; then
    grep -q "prism_cgroup_drops_total" "${metrics_file}"
else
    echo "no cgroup snapshots exported during run; kernel drop metric unavailable in final scrape" | tee -a "${log_file}"
fi

curl --fail --silent --show-error "${metrics_url}" | grep -q "prism_"
echo "chaos soak completed profile=${profile} duration=${duration_seconds}s peak_rss_kb=${peak_rss}" | tee -a "${log_file}"
