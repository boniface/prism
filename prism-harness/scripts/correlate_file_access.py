#!/usr/bin/env python3
import csv
import re
import sys
import subprocess
import statistics

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
# Matches the marker filename anywhere within the path field, e.g.
# path=/tmp/prism-harness/file-markers/p0000000
MARKER_RE = re.compile(r'path=\S*/(p[0-9a-f]{7})(?:\s|$)')

def percentile(sorted_data, pct):
    if not sorted_data:
        return None
    k = (len(sorted_data) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_data) - 1)
    if f == c:
        return sorted_data[f]
    return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)

def correlate(ground_truth_file, prism_log_file, output_file):
    ground_truth = {}
    with open(ground_truth_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ground_truth[row['marker']] = {
                't0_monotonic_ns': int(row['t0_monotonic_ns']),
                't0_realtime_ns': int(row['t0_realtime_ns']),
            }

    print(f"Ground truth markers: {list(ground_truth.keys())[:5]}...")

    print(f"Reading Prism log file: {prism_log_file}")
    try:
        with open(prism_log_file, 'r') as f:
            lines = f.readlines()
    except PermissionError:
        result = subprocess.run(['sudo', 'cat', prism_log_file], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error reading file: {result.stderr}")
            return
        lines = result.stdout.splitlines()

    print(f"Read {len(lines)} lines from log file")

    lines = [ANSI_RE.sub('', line) for line in lines]

    print("\n=== DEBUG: First 3 lines containing 'file access event' ===")
    count = 0
    for line in lines:
        if 'file access event' in line:
            print(f"  Line: {line[:200]}...")
            count += 1
            if count >= 3:
                break

    prism_events = {}
    marker_count = 0
    for line in lines:
        if 'file access event' not in line:
            continue

        match = MARKER_RE.search(line)
        if not match:
            continue
        marker = match.group(1)

        ts_match = re.search(r'timestamp_ns=(\d+)', line)
        if not ts_match:
            continue
        ts_ns = int(ts_match.group(1))

        pid_match = re.search(r'\bpid=(\d+)', line)
        pid = pid_match.group(1) if pid_match else ''

        prism_events[marker] = {
            'prism_ts_ns': ts_ns,
            'prism_pid': pid
        }
        marker_count += 1

    print(f"\nFound {marker_count} marker events")
    print(f"Prism markers: {list(prism_events.keys())[:5]}...")

    results = []
    for seq, (marker, gt) in enumerate(ground_truth.items()):
        if marker in prism_events:
            pe = prism_events[marker]
            latency_ns = pe['prism_ts_ns'] - gt['t0_monotonic_ns']
            latency_us = latency_ns / 1000.0
            latency_ms = latency_us / 1000.0
            results.append({
                'seq': seq,
                'marker': marker,
                'prism_pid': pe['prism_pid'],
                'gt_t0_ns': gt['t0_monotonic_ns'],
                'prism_ts_ns': pe['prism_ts_ns'],
                'latency_ns': latency_ns,
                'latency_us': latency_us,
                'latency_ms': latency_ms,
                'matched': True
            })
        else:
            results.append({
                'seq': seq,
                'marker': marker,
                'prism_pid': '',
                'gt_t0_ns': gt['t0_monotonic_ns'],
                'prism_ts_ns': '',
                'latency_ns': '',
                'latency_us': '',
                'latency_ms': '',
                'matched': False
            })

    with open(output_file, 'w') as f:
        fieldnames = ['seq', 'marker', 'prism_pid', 'gt_t0_ns', 'prism_ts_ns',
                      'latency_ns', 'latency_us', 'latency_ms', 'matched']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    matched = sum(1 for r in results if r['matched'])
    total = len(results)
    print(f"\n=== Correlation Summary ===")
    print(f"Total events: {total}")
    print(f"Matched: {matched}")
    print(f"Missed: {total - matched}")
    if total > 0:
        print(f"Capture rate: {matched/total*100:.1f}%")

    if matched > 0:
        latencies = [r['latency_us'] for r in results if r['matched']]
        sorted_latencies = sorted(latencies)

        avg_latency = sum(latencies) / len(latencies)
        median_latency = statistics.median(latencies)
        stdev_latency = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
        min_latency = sorted_latencies[0]
        max_latency = sorted_latencies[-1]

        p50 = percentile(sorted_latencies, 50)
        p90 = percentile(sorted_latencies, 90)
        p95 = percentile(sorted_latencies, 95)
        p99 = percentile(sorted_latencies, 99)

        print(f"\nLatency statistics (µs):")
        print(f"  Mean:    {avg_latency:.2f}")
        print(f"  Median:  {median_latency:.2f}")
        print(f"  Stdev:   {stdev_latency:.2f}")
        print(f"  Min:     {min_latency:.2f}")
        print(f"  Max:     {max_latency:.2f}")
        print(f"\nPercentiles (µs):")
        print(f"  p50:     {p50:.2f}")
        print(f"  p90:     {p90:.2f}")
        print(f"  p95:     {p95:.2f}")
        print(f"  p99:     {p99:.2f}")

        p25 = percentile(sorted_latencies, 25)
        p75 = percentile(sorted_latencies, 75)
        iqr = p75 - p25
        outlier_threshold = p75 + 1.5 * iqr
        outliers = [r for r in results if r['matched'] and r['latency_us'] > outlier_threshold]

        print(f"\nOutlier threshold (p75 + 1.5*IQR): {outlier_threshold:.2f} µs")
        print(f"Outliers: {len(outliers)} / {matched} ({len(outliers)/matched*100:.1f}%)")
        if outliers:
            print(f"\nOutlier detail (seq, marker, latency_us):")
            for r in sorted(outliers, key=lambda x: x['seq']):
                print(f"  seq={r['seq']:>3}  {r['marker']}: {r['latency_us']:.2f} µs")

        print(f"\nFirst 5 results (seq order):")
        for r in sorted(results, key=lambda x: x['seq'])[:5]:
            if r['matched']:
                print(f"  seq={r['seq']:>3}  {r['marker']}: {r['latency_us']:.2f} µs")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: correlate_file_access.py <ground_truth.csv> <prism_agent.log> [output.csv]")
        sys.exit(1)

    gt_file = sys.argv[1]
    log_file = sys.argv[2]
    out_file = sys.argv[3] if len(sys.argv) > 3 else "correlated_file_access_results.csv"

    correlate(gt_file, log_file, out_file)
