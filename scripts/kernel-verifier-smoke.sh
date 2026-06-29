#!/usr/bin/env bash
set -euo pipefail

log_dir="${PRISM_VERIFIER_LOG_DIR:-target/verifier-logs}"
kernel="$(uname -r)"
log_file="${log_dir}/verifier-${kernel}.log"
required="${PRISM_VERIFIER_REQUIRED:-0}"

mkdir -p "${log_dir}"

skip() {
    echo "$1" | tee "${log_file}"
    if [ "${required}" = "1" ]; then
        exit 1
    fi
    exit 0
}

if [ "$(uname -s)" != "Linux" ]; then
    skip "kernel verifier smoke requires Linux; current OS is $(uname -s)"
fi

if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    skip "kernel verifier smoke requires root or sudo"
fi

if [ ! -r /sys/kernel/btf/vmlinux ]; then
    skip "kernel verifier smoke requires readable /sys/kernel/btf/vmlinux"
fi

if ! mountpoint -q /sys/fs/bpf; then
    skip "kernel verifier smoke requires bpffs mounted at /sys/fs/bpf"
fi

make ebpf 2>&1 | tee "${log_file}"
PRISM_EBPF_OBJECT="${PRISM_EBPF_OBJECT:-target/bpfel-unknown-none/release/libprism_ebpf.so}"
PRISM_BPF_PIN_PATH="${PRISM_BPF_PIN_PATH:-/sys/fs/bpf/prism-verifier-${kernel}}"
export PRISM_EBPF_OBJECT PRISM_BPF_PIN_PATH

run_agent() {
    PRISM_EBPF_OBJECT="${PRISM_EBPF_OBJECT}" \
        PRISM_BPF_PIN_PATH="${PRISM_BPF_PIN_PATH}" \
        PRISM_BPF_EPHEMERAL=true \
        PRISM_CAPTURE_PROCESS_EXEC=false \
        timeout --signal=INT "${PRISM_VERIFIER_TIMEOUT_SECONDS:-15}" \
        ./target/release/prism-agent
}

if [ "$(id -u)" -eq 0 ]; then
    make build 2>&1 | tee -a "${log_file}"
    run_agent 2>&1 | tee -a "${log_file}"
else
    make build 2>&1 | tee -a "${log_file}"
    sudo --preserve-env=PRISM_EBPF_OBJECT,PRISM_BPF_PIN_PATH,PRISM_BPF_EPHEMERAL,PRISM_CAPTURE_PROCESS_EXEC \
        bash -c "$(declare -f run_agent); run_agent" 2>&1 | tee -a "${log_file}"
fi
