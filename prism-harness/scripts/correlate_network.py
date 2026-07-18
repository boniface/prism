#!/usr/bin/env python3
"""
Correlates ground-truth network-connection markers (identified by
destination port) against Prism's "network connection event" log lines.
Strips ANSI codes defensively (same fix as exec/file-access logs needed).
"""
import sys
import re
import csv
import statistics

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
LINE_RE = re.compile(
    r'network connection event.*?dst=(?P<ip>[\d.]+):(?P<port>\d+).*?timestamp_ns=(?P<ts>\d+)'
)


def percentile(sorted_list, pct):
    if not sorted_list:
        return 0.0
    k = (len(sorted_list) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(sorted_list) - 1)
    if f == c:
        return sorted_list[f]
    return sorted_list[f] + (sorted_list[c] - sorted_list[f]) * (k - f)


def correlate(gt_file, log_file, output_file):
    with open(gt_file) as f:
        gt_rows = list(csv.DictReader(f))
    print(f"Ground truth markers: {[r['marker'] for r in gt_rows[:5]]}...")

    print(f"Reading Prism log file: {log_file}")
    with open(log_file, errors="replace") as f:
        lines = f.readlines()
    lines = [ANSI_RE.sub('', line) for line in lines]
    print(f"Read {len(lines)} lines from log file")

    port_to_ts = {}
    for line in lines:
        m = LINE_RE.search(line)
        if m:
            port = int(m.group("port"))
            ts = int(m.group("ts"))
            if port not in port_to_ts:  # keep first occurrence
                port_to_ts[port] = ts

    print(f"Found {len(port_to_ts)} network connection marker events")

    results = []
    for r in gt_rows:
        port = int(r["port"])
        gt_t0 = int(r["t0_monotonic_ns"])
        prism_ts = port_to_ts.get(port)
        matched = prism_ts is not None
        latency_ns = (prism_ts - gt_t0) if matched else None
        results.append({
            "seq": r["seq"],
            "marker": r["marker"],
            "port": port,
            "gt_t0_ns": gt_t0,
            "prism_ts_ns": prism_ts if matched else "",
            "latency_ns": latency_ns if matched else "",
            "latency_us": (latency_ns / 1000) if matched else "",
            "latency_ms": (latency_ns / 1_000_000) if matched else "",
            "matched": matched,
        })

    with open(output_file, "w", newline="") as f:
        fieldnames = ["seq", "marker", "port", "gt_t0_ns", "prism_ts_ns",
                      "latency_ns", "latency_us", "latency_ms", "matched"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(results)

    matched = sum(1 for r in results if r["matched"])
    total = len(results)
    print("\n=== Correlation Summary ===")
    print(f"Total events: {total}")
    print(f"Matched: {matched}")
    print(f"Missed: {total - matched}")
    if total:
        print(f"Capture rate: {matched/total*100:.1f}%")

    if matched:
        lat = [r["latency_us"] for r in results if r["matched"]]
        lat_sorted = sorted(lat)
        print("\nLatency statistics (\u00b5s):")
        print(f"  Mean:    {sum(lat)/len(lat):.2f}")
        print(f"  Median:  {statistics.median(lat):.2f}")
        print(f"  Stdev:   {statistics.stdev(lat) if len(lat) > 1 else 0:.2f}")
        print(f"  Min:     {lat_sorted[0]:.2f}")
        print(f"  Max:     {lat_sorted[-1]:.2f}")
        print("\nPercentiles (\u00b5s):")
        for p in (50, 90, 95, 99):
            print(f"  p{p}:     {percentile(lat_sorted, p):.2f}")

        p25 = percentile(lat_sorted, 25)
        p75 = percentile(lat_sorted, 75)
        iqr = p75 - p25
        outlier_threshold = p75 + 1.5 * iqr
        outliers = [r for r in results if r["matched"] and r["latency_us"] > outlier_threshold]
        print(f"\nOutlier threshold (p75 + 1.5*IQR): {outlier_threshold:.2f} \u00b5s")
        print(f"Outliers: {len(outliers)} / {matched} ({len(outliers)/matched*100:.1f}%)")
        if outliers:
            print("\nOutlier detail (seq, marker, latency_us):")
            for r in sorted(outliers, key=lambda x: x["seq"]):
                print(f"  seq={r['seq']:>3}  {r['marker']}: {r['latency_us']:.2f} \u00b5s")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: correlate_network.py <ground_truth_network.csv> <prism_agent.log> [output.csv]")
        sys.exit(1)

    gt_file = sys.argv[1]
    log_file = sys.argv[2]
    out_file = sys.argv[3] if len(sys.argv) > 3 else "correlated_network_results.csv"
    correlate(gt_file, log_file, out_file)
