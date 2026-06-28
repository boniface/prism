# Crash Recovery Smoke Test

`make crash-recovery-smoke` validates that repeated forced termination does not grow the Prism-owned BPF pin set after startup reconciliation.

## Privileges

Run this test on Linux as root. The test needs the same privileges as a production agent load path: readable `/sys/kernel/btf/vmlinux`, mounted bpffs at `/sys/fs/bpf`, eBPF load capability, and permission to send `SIGKILL` to the agent process. Non-Linux or unprivileged runs skip unless `PRISM_CRASH_RECOVERY_REQUIRED=1`.

## Flow

1. Build the release agent and eBPF object with `make build`.
2. Start the agent with an isolated pin root, defaulting to `/sys/fs/bpf/prism-crash-recovery`.
3. Verify `/metrics` returns Prometheus output.
4. Kill the agent with `SIGKILL`.
5. Restart the agent long enough for startup reconciliation.
6. Assert the Prism-owned pinned map/link count under the pin root is not higher than the baseline.

## Useful Environment

- `PRISM_CRASH_RECOVERY_ITERATIONS`: restart loop count, default `3`.
- `PRISM_BPF_PIN_PATH`: isolated pin root to test, default `/sys/fs/bpf/prism-crash-recovery`.
- `PRISM_PROMETHEUS_LISTEN_ADDR`: metrics bind address, default `127.0.0.1:19090`.
- `PRISM_CRASH_LOG_DIR`: log artifact directory, default `target/crash-recovery-logs`.
- `PRISM_CRASH_RECOVERY_REQUIRED=1`: convert platform skips into failures for CI runners dedicated to this test.
