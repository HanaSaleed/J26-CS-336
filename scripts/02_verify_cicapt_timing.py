#!/usr/bin/env python3
r"""Read-only, sample-only CICAPT timestamp and feature sanity checks.

Save as: <project>/scripts/02_verify_cicapt_timing.py
Run from project: .\.venv\Scripts\python.exe .\scripts\02_verify_cicapt_timing.py
No third-party packages, no writes, and no full CSV scan.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def numeric(row: dict[str, str], key: str) -> float | None:
    try:
        return float(row[key].strip())
    except (KeyError, ValueError, AttributeError):
        return None


def attack_metadata(path: Path) -> tuple[float, float] | None:
    print("\n=== ATTACK METADATA ===")
    if not path.is_file():
        print(f"NOT FOUND: {path}")
        print("Move attack_info.csv to data/metadata/cicapt/ and rerun.")
        return None
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    times = [v for row in rows if (v := numeric(row, "Time of Attack")) is not None]
    if not times:
        print("No valid numeric 'Time of Attack' values found.")
        return None
    lo, hi = min(times), max(times)
    print(f"Metadata records: {len(rows):,}")
    print(f"Distinct event timestamps: {len(set(times)):,}")
    print(f"First attack timestamp: {lo:.3f} = {utc(lo)}")
    print(f"Last attack timestamp:  {hi:.3f} = {utc(hi)}")
    print("Tactics:", dict(Counter(row.get("Tactic Name", "") for row in rows)))
    print("Note: an attack execution event is NOT automatically a malicious network flow label.")
    return lo, hi


def inspect_csv(path: Path, limit: int, attack_window: tuple[float, float] | None) -> None:
    print(f"\n=== {path.name} ===")
    if not path.is_file():
        print("NOT FOUND:", path)
        return
    count, lower, upper, prev_ts = 0, None, None, None
    first_ts, backtracks, in_window = None, 0, 0
    labels: Counter[str] = Counter()
    # Counts are only for the first `limit` rows, not the entire file.
    compare = {name: {"valid": 0, "timestamp_like": 0, "zeros": 0, "huge": 0}
               for name in ("IAT", "flow_idle_time", "max_duration", "min_duration", "average_duration", "flow_duration")}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            print("EMPTY CSV")
            return
        if "ts" not in reader.fieldnames:
            print("Missing 'ts' header; found:", reader.fieldnames[:10])
            return
        for row in reader:
            if count >= limit:
                break
            count += 1
            ts = numeric(row, "ts")
            labels[row.get("label", "<missing>")] += 1
            if ts is None:
                continue
            if first_ts is None:
                first_ts = ts
            lower = ts if lower is None else min(lower, ts)
            upper = ts if upper is None else max(upper, ts)
            if prev_ts is not None and ts < prev_ts:
                backtracks += 1
            prev_ts = ts
            if attack_window and attack_window[0] <= ts <= attack_window[1]:
                in_window += 1
            for name, stats in compare.items():
                val = numeric(row, name)
                if val is None:
                    continue
                stats["valid"] += 1
                if abs(val - ts) < 0.001:
                    stats["timestamp_like"] += 1
                if val == 0:
                    stats["zeros"] += 1
                if abs(val) > 1_000_000_000:
                    stats["huge"] += 1
    print(f"Rows checked: {count:,} (FIRST rows only; NOT complete dataset)")
    if first_ts is None:
        print("No parseable 'ts' values in sample.")
        return
    print(f"First row time:    {utc(first_ts)}")
    print(f"Sample min time:   {utc(lower)}")
    print(f"Sample max time:   {utc(upper)}")
    print(f"Backward ts jumps in sample: {backtracks:,}")
    print("Sample label counts:", dict(labels))
    if attack_window:
        print(f"Rows within metadata's first-to-last attack time window: {in_window:,} / {count:,}")
        print("Caution: time overlap alone does NOT prove an event matches an attack.")
    print("Feature checks: feature = ts / zeros / >1e9 (from sampled rows)")
    for name, stats in compare.items():
        print(f"  {name:18s}: {stats['timestamp_like']:>6,} / {stats['zeros']:>6,} / {stats['huge']:>6,} (valid {stats['valid']:,})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, default=10000, help="First N rows per CSV, default 10000")
    args = parser.parse_args()
    if args.sample < 1 or args.sample > 100000:
        parser.error("--sample must be between 1 and 100000")
    project = Path(__file__).resolve().parent.parent
    print("CICAPT metadata/time check (READ ONLY, SAMPLE ONLY)")
    print("Project root:", project)
    window = attack_metadata(project / "data" / "metadata" / "cicapt" / "attack_info.csv")
    for name in ("cicapt_IIOT_phase1_NetworkData.csv", "cicapt_IIOT_phase2_NetworkData.csv"):
        inspect_csv(project / "data" / "raw" / name, args.sample, window)
    print("\n=== NEXT ===")
    print("Share this terminal output. The previous full dataset audit has already been received.")
    print("We will use the full audit's timestamp ranges instead of re-reading ~9 GB.")


if __name__ == "__main__":
    main()
