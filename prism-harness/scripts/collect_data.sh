#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-100}"
INTERVAL_MS="${2:-10}"
OUTPUT_DIR="/home/mikey/prism-harness/data/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"
chmod 755 "$OUTPUT_DIR"

echo "=== Prism Data Collection ==="
echo "Events: $COUNT"
echo "Interval: ${INTERVAL_MS}ms"
echo "Output: $OUTPUT_DIR"
echo ""

# Step 1: Start the agent
echo "Starting Prism agent..."
cd ~/prism

# Run agent in background and wait
sudo RUST_LOG=info \
    PRISM_EBPF_OBJECT=target/bpfel-unknown-none/release/libprism_ebpf.so \
    PRISM_CAPTURE_PROCESS_EXEC=true \
    PRISM_CAPTURE_COMMAND_LINE=true \
    ./target/release/prism-agent 2>&1 | sudo tee "$OUTPUT_DIR/prism_agent.log" &
AGENT_PID=$!

echo "Agent PID: $AGENT_PID"
sleep 4

# Step 2: Run the generator
echo "Running generator..."
cd ~/prism-harness
./target/release/generate_exec \
    --count "$COUNT" \
    --interval-ms "$INTERVAL_MS" \
    --output "$OUTPUT_DIR/ground_truth.csv"

# Step 3: Stop the agent
echo "Stopping Prism agent..."
sudo kill -INT "$AGENT_PID" 2>/dev/null || true
sleep 3

# Force kill if still running
sudo pkill -9 prism-agent 2>/dev/null || true
sleep 1

# Step 4: Extract events
echo "Extracting Prism exec events..."
if [ -f "$OUTPUT_DIR/prism_agent.log" ]; then
    sudo grep "process exec event" "$OUTPUT_DIR/prism_agent.log" | grep -E "comm=p[0-9a-f]{7}" > "$OUTPUT_DIR/prism_events.txt" || true
    sudo chown mikey:mikey "$OUTPUT_DIR/prism_events.txt" 2>/dev/null || true
fi

echo ""
echo "=== Results ==="
echo "Ground truth events: $(tail -n +2 "$OUTPUT_DIR/ground_truth.csv" 2>/dev/null | wc -l || echo 0)"
echo "Prism events captured: $(cat "$OUTPUT_DIR/prism_events.txt" 2>/dev/null | wc -l || echo 0)"
echo ""
echo "Sample Prism events (first 10):"
head -10 "$OUTPUT_DIR/prism_events.txt" 2>/dev/null || echo "No events captured"
echo ""
echo "Results saved to: $OUTPUT_DIR/"
