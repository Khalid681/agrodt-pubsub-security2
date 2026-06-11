#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from common import METRICS_FILE, PROJECT_ROOT


def safe_float(x):
    try:
        return float(x)
    except Exception:
        return None


def main() -> None:
    out = PROJECT_ROOT / "results" / "benchmark_summary.csv"
    if not METRICS_FILE.exists():
        print(f"No metrics found: {METRICS_FILE}")
        print("Run publisher and authorized_subscriber first.")
        return

    groups = defaultdict(list)
    with METRICS_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            mode = row.get("Mode", "unknown")
            groups[mode].append(row)

    fieldnames = [
        "Mode", "TotalMessages", "Accepted", "Rejected",
        "AvgLatencyMs", "AvgMessageSizeBytes", "AvgCPUPercent", "AvgMemoryMB"
    ]

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for mode, rows in sorted(groups.items()):
            lat = [safe_float(r.get("LatencyMs")) for r in rows if safe_float(r.get("LatencyMs")) is not None]
            size = [safe_float(r.get("MessageSizeBytes")) for r in rows if safe_float(r.get("MessageSizeBytes")) is not None]
            cpu = [safe_float(r.get("CPUPercent")) for r in rows if safe_float(r.get("CPUPercent")) is not None]
            mem = [safe_float(r.get("MemoryMB")) for r in rows if safe_float(r.get("MemoryMB")) is not None]
            writer.writerow({
                "Mode": mode,
                "TotalMessages": len(rows),
                "Accepted": sum(1 for r in rows if r.get("Status") == "ACCEPTED"),
                "Rejected": sum(1 for r in rows if r.get("Status") == "REJECTED"),
                "AvgLatencyMs": round(sum(lat)/len(lat), 3) if lat else "",
                "AvgMessageSizeBytes": round(sum(size)/len(size), 2) if size else "",
                "AvgCPUPercent": round(sum(cpu)/len(cpu), 3) if cpu else "",
                "AvgMemoryMB": round(sum(mem)/len(mem), 3) if mem else "",
            })

    print(f"Benchmark summary written to: {out}")


if __name__ == "__main__":
    main()
