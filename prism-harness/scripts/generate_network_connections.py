#!/usr/bin/env python3
"""
Generates ground-truth network connection events by attempting TCP connects
to 127.0.0.1 on a sequential range of ports. Nothing needs to be listening —
the connect() will fail fast (ECONNREFUSED), but sys_enter_connect fires on
syscall entry regardless, so Prism still captures it. Each port number acts
as the "marker" for correlation, since there's no string field to embed a
marker in the way file paths allowed.
"""
import socket
import sys
import time
import csv
import argparse


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=50)
    p.add_argument("--interval-ms", type=int, default=20)
    p.add_argument("--base-port", type=int, default=21000)
    p.add_argument("--out", default="ground_truth_network.csv")
    args = p.parse_args()

    rows = []
    for seq in range(args.count):
        port = args.base_port + seq
        marker = f"p{seq:07x}"
        t0_mono = time.monotonic_ns()
        t0_real = time.time_ns()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect(("127.0.0.1", port))
        except OSError:
            pass  # expected — refused/timeout, syscall still happened
        finally:
            s.close()

        rows.append({
            "seq": seq,
            "marker": marker,
            "port": port,
            "t0_monotonic_ns": t0_mono,
            "t0_realtime_ns": t0_real,
        })
        time.sleep(args.interval_ms / 1000)

    with open(args.out, "w", newline="") as f:
        fieldnames = ["seq", "marker", "port", "t0_monotonic_ns", "t0_realtime_ns"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"generated {args.count} network connection events -> {args.out}")


if __name__ == "__main__":
    main()
