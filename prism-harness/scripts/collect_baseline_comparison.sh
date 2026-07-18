#!/usr/bin/env bash
# collect_baseline_comparison.sh
#
# Runs a single process-exec workload while Prism and auditd both watch,
# then reports how many of the generated events each one captured.
#
# Usage:
#   ./collect_baseline_comparison.sh [count] [interval_ms]
#
# Requires:
#   - auditd installed, active, with a rule tagged "prism_exec" watching execve
#     (sudo auditctl -a always,exit -F arch=b64 -S execve -k prism_exec)
#   - ~/prism-harness/target/release/generate_exec built
#   - ~/prism/target/release/prism-agent built

set -euo pipefail

COUNT="${1:-50}"
INTERVAL_MS="${2:-20}"

PRISM_DIR="$HOME/prism"
HARNESS_DIR="$HOME/prism-harness"
OUTPUT_DIR="$HARNESS_DIR/data/baseline_$(date +%Y%m%d_%H%M%S)"
AGENT_LOG="$OUTPUT_DIR/prism_agent.log"
GROUND_TRUTH="$OUTPUT_DIR/ground_truth.csv"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"

mkdir -p "$OUTPUT_DIR"
chmod 755 "$OUTPUT_DIR"

echo "=== Prism vs auditd Baseline Comparison ==="
echo "Events:   $COUNT"
echo "Interval: ${INTERVAL_MS}ms"
echo "Output:   $OUTPUT_DIR"
echo ""

# --- Step 0: sanity checks -------------------------------------------------

if ! command -v auditctl >/dev/null 2>&1; then
    echo "ERROR: auditctl not found. Install auditd first (sudo apt install auditd)." >&2
    exit 1
fi

if ! sudo auditctl -l 2>/dev/null | grep -q "key=prism_exec"; then
    echo "No prism_exec audit rule found — adding it now."
    sudo auditctl -a always,exit -F arch=b64 -S execve -k prism_exec
fi

if [ ! -x "$HARNESS_DIR/target/release/generate_exec" ]; then
    echo "ERROR: generate_exec binary not found at $HARNESS_DIR/target/release/generate_exec" >&2
    exit 1
fi

# --- Step 1: build a fresh release binary ------------------------------------
# Always rebuild in release mode before running, so this script never
# silently tests a stale binary from before a code change (e.g. the
# memory/disk metrics fix). cargo no-ops quickly if nothing changed.

echo "Building prism-agent (release)..."
cd "$PRISM_DIR"
cargo build --release --package prism-agent

if [ ! -x "$PRISM_DIR/target/release/prism-agent" ]; then
    echo "ERROR: build succeeded but binary not found at $PRISM_DIR/target/release/prism-agent" >&2
    exit 1
fi

# --- Step 2: start the Prism agent ------------------------------------------

echo "Starting Prism agent..."
cd "$PRISM_DIR"
sudo RUST_LOG=info \
    PRISM_EBPF_OBJECT=target/bpfel-unknown-none/release/libprism_ebpf.so \
    PRISM_CAPTURE_PROCESS_EXEC=true \
    PRISM_CAPTURE_COMMAND_LINE=true \
    ./target/release/prism-agent > "$AGENT_LOG" 2>&1 &
AGENT_PID=$!
echo "Agent PID: $AGENT_PID"

# Give it a moment to finish loading eBPF programs before we generate load
sleep 4

# --- Step 3: mark the precise start time for the auditd query --------------

# auditd timestamps are wall-clock, so record "now" right before the
# generator runs. A few seconds of slack on either side is fine since we
# match on the generated marker names, not just the time window.
AUDIT_START_TS="$(date +%H:%M:%S)"

# --- Step 4: run the workload ------------------------------------------------

echo "Running generate_exec (count=$COUNT, interval=${INTERVAL_MS}ms)..."
cd "$HARNESS_DIR"
./target/release/generate_exec \
    --count "$COUNT" \
    --interval-ms "$INTERVAL_MS" \
    --output "$GROUND_TRUTH"

# Let both collectors catch up / flush before we stop anything
sleep 2

# --- Step 5: stop the Prism agent -------------------------------------------

echo "Stopping Prism agent..."
sudo kill -INT "$AGENT_PID" 2>/dev/null || true
sleep 3
sudo pkill -9 -f "target/release/prism-agent" 2>/dev/null || true
sleep 1
sudo chown "$(whoami):$(whoami)" "$AGENT_LOG" 2>/dev/null || true

# --- Step 6: count ground truth markers -------------------------------------

GT_COUNT="$(tail -n +2 "$GROUND_TRUTH" | cut -d',' -f1 | sort -u | wc -l)"

# --- Step 7: count Prism captures (only this run's log file, no globbing) --

PRISM_COUNT="$(sudo grep "process exec event" "$AGENT_LOG" 2>/dev/null \
    | grep -oE "comm=p[0-9a-f]+" | sort -u | wc -l || echo 0)"

# --- Step 8: count auditd captures, scoped to this run's markers -----------
# We match against the same marker set as ground truth, not just a time
# window, so leftover events from earlier runs never get counted.

MARKERS_FILE="$OUTPUT_DIR/markers.txt"
tail -n +2 "$GROUND_TRUTH" | cut -d',' -f1 | sort -u > "$MARKERS_FILE"

AUDIT_RAW="$OUTPUT_DIR/ausearch_raw.txt"
sudo ausearch -k prism_exec -ts "$AUDIT_START_TS" > "$AUDIT_RAW" 2>/dev/null || true

AUDIT_COUNT="$(grep -oE 'comm="p[0-9a-f]+"' "$AUDIT_RAW" \
    | tr -d '"' | sed 's/comm=//' | sort -u | comm -12 - "$MARKERS_FILE" | wc -l)"

# --- Step 9: write summary ---------------------------------------------------

{
    echo "=== Baseline Comparison Summary ==="
    echo "Run at:            $(date)"
    echo "Generated events:  $GT_COUNT"
    echo "Prism captured:    $PRISM_COUNT / $GT_COUNT"
    echo "auditd captured:   $AUDIT_COUNT / $GT_COUNT"
    echo ""
    if [ "$GT_COUNT" -gt 0 ]; then
        printf "Prism coverage:    %.1f%%\n" "$(echo "scale=1; $PRISM_COUNT * 100 / $GT_COUNT" | bc)"
        printf "auditd coverage:   %.1f%%\n" "$(echo "scale=1; $AUDIT_COUNT * 100 / $GT_COUNT" | bc)"
    fi
    echo ""
    echo "Details saved in: $OUTPUT_DIR"
    echo "  - ground_truth.csv   (generated event markers)"
    echo "  - prism_agent.log    (raw Prism agent output, this run only)"
    echo "  - ausearch_raw.txt   (raw auditd query output, this run only)"
    echo "  - markers.txt        (ground-truth marker list used for matching)"
} | tee "$SUMMARY_FILE"
