#!/usr/bin/env python3
"""J26-CS-336 | Phase 5, Step 5.10 | READ-ONLY CICAPT row structure probe.

Examines the first N CICAPT Phase-2 CSV records. Does not modify CSVs,
rename columns, create files, train models, or assign labels.

Interpretation caution: packet-like statistics do not prove raw packet
correspondence without checking the generating pipeline / original PCAP.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


REQUIRED = [
    "ts", "Source IP", "Destination IP", "Source Port", "Destination Port",
    "Protocol Type", "Tot size", "Number", "flow_duration", "label",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "urg_flag_number", "ece_flag_number", "cwr_flag_number",
]
FLAGS = [name for name in REQUIRED if name.endswith("_flag_number")]


def number(raw: str) -> float | None:
    try:
        value = float(raw)
        return value if math.isfinite(value) else None
    except (TypeError, ValueError):
        return None


def utc(ts: float | None) -> str:
    if ts is None:
        return "unknown"
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "timestamp out of range"


def key_for(row: dict[str, str]) -> tuple | None:
    """Five-tuple communication key, bidirectional to assess recurring conversations."""
    try:
        src = row["Source IP"].strip()
        dst = row["Destination IP"].strip()
        ipaddress.ip_address(src)
        ipaddress.ip_address(dst)
        sport = int(row["Source Port"])
        dport = int(row["Destination Port"])
        proto = int(row["Protocol Type"])
        if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
            return None
        ends = tuple(sorted(((src, sport), (dst, dport))))
        return (proto, *ends)
    except (KeyError, ValueError, TypeError):
        return None


def inspect(csv_file: Path, limit: int) -> None:
    if not csv_file.is_file():
        raise FileNotFoundError(f"CSV not found: {csv_file}")

    with csv_file.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"Required CSV columns missing: {missing}")

        total = 0
        malformed_width = 0
        ts_valid = 0
        ts_same_prev = 0
        ts_backwards = 0
        ts_first = None
        ts_prev = None
        ts_min = None
        ts_max = None
        size_valid = 0
        size_positive_integer = 0
        size_non_integer = 0
        size_min = None
        size_max = None
        tcp_rows = 0
        tcp_all_binary = 0
        number_0to19 = 0
        number_samples = []
        label_counts = Counter()
        flow_occurrences = Counter()
        flow_first_ts = {}
        flow_compared = 0
        flow_duration_match = 0
        flow_duration_mismatch = 0
        examples = []

        for row in reader:
            if total >= limit:
                break
            total += 1
            if None in row or any(row.get(k) is None for k in REQUIRED):
                malformed_width += 1
                continue

            label_counts[row["label"].strip()] += 1
            ts = number(row["ts"])
            size = number(row["Tot size"])
            duration = number(row["flow_duration"])
            proto = number(row["Protocol Type"])
            if ts is not None:
                ts_valid += 1
                if ts_first is None:
                    ts_first = ts
                if ts_prev is not None:
                    if ts == ts_prev:
                        ts_same_prev += 1
                    elif ts < ts_prev:
                        ts_backwards += 1
                ts_prev = ts
                ts_min = ts if ts_min is None else min(ts_min, ts)
                ts_max = ts if ts_max is None else max(ts_max, ts)

            if size is not None:
                size_valid += 1
                size_min = size if size_min is None else min(size_min, size)
                size_max = size if size_max is None else max(size_max, size)
                if size > 0 and size.is_integer():
                    size_positive_integer += 1
                elif not size.is_integer():
                    size_non_integer += 1

            n = number(row["Number"])
            if n is not None and n.is_integer() and 0 <= n <= 19:
                number_0to19 += 1
            if len(number_samples) < 25:
                number_samples.append(row["Number"])

            if proto == 6:
                tcp_rows += 1
                flags = [number(row[flag]) for flag in FLAGS]
                if all(v in (0.0, 1.0) for v in flags):
                    tcp_all_binary += 1

            flow_key = key_for(row)
            if flow_key is not None and ts is not None:
                flow_occurrences[flow_key] += 1
                if flow_key not in flow_first_ts:
                    flow_first_ts[flow_key] = ts
                # Compare with earliest seen timestamp in this sample only. Since source
                # processing may reset state, a match/mismatch is indicative, not proof.
                if flow_occurrences[flow_key] >= 2 and duration is not None:
                    flow_compared += 1
                    expected = ts - flow_first_ts[flow_key]
                    if abs(expected - duration) < 0.01:
                        flow_duration_match += 1
                    else:
                        flow_duration_mismatch += 1

            if len(examples) < 6:
                examples.append((total, utc(ts), row["Source IP"], row["Source Port"],
                                 row["Destination IP"], row["Destination Port"],
                                 row["Protocol Type"], row["Tot size"], row["flow_duration"]))

    print("=== CICAPT RECORD-STRUCTURE PROBE (READ ONLY) ===")
    print(f"CSV: {csv_file}")
    print(f"Rows examined: {total:,} (FIRST rows only)")
    print(f"Required columns found: {len(REQUIRED)}/{len(REQUIRED)}")
    print(f"Rows with malformed width: {malformed_width:,}")
    print(f"Labels: {dict(label_counts)}")
    print("\n=== TIMESTAMP BEHAVIOUR ===")
    print(f"Numeric finite timestamps: {ts_valid:,}/{total:,}")
    print(f"Sample earliest: {utc(ts_min)}")
    print(f"Sample latest:   {utc(ts_max)}")
    print(f"Adjacent identical timestamps: {ts_same_prev:,}")
    print(f"Backward jumps in file order: {ts_backwards:,}")
    print("\n=== PACKET-LIKE FIELD CHECKS ===")
    print(f"Positive integer Tot size: {size_positive_integer:,}/{size_valid:,} valid values")
    print(f"Noninteger Tot size: {size_non_integer:,}")
    print(f"Tot size range: {size_min} to {size_max}")
    print(f"TCP rows with all eight flag fields binary (0/1): {tcp_all_binary:,}/{tcp_rows:,}")
    print(f"Number in 0..19: {number_0to19:,}/{total:,}")
    print(f"First 25 Number values: {number_samples}")
    print("\n=== REPEATED NETWORK CONVERSATIONS ===")
    print(f"Distinct valid bidirectional 5-tuples in sample: {len(flow_occurrences):,}")
    print(f"5-tuples occurring at least twice: {sum(1 for n in flow_occurrences.values() if n >= 2):,}")
    print(f"Subsequent rows compared to time since first observed row: {flow_compared:,}")
    print(f"Matches within 0.01s: {flow_duration_match:,}")
    print(f"Does not match within 0.01s: {flow_duration_mismatch:,}")
    print("Note: this comparison is sample-relative; source processing may reset flow state.")
    print("\n=== EXAMPLE RECORDS ===")
    for idx, when, src, sport, dst, dport, proto, size, dur in examples:
        print(f"#{idx:,}: {when}  {src}:{sport} -> {dst}:{dport} "
              f"proto={proto} size={size} flow_duration={dur}")
    print("\n=== INTERPRETATION RULE ===")
    print("Binary TCP flags, individual integer packet sizes, and changing timestamps")
    print("are consistent with packet-like observations, but DO NOT PROVE one CSV")
    print("row = one original network packet. Exact mapping requires a verified")
    print("export pipeline or corresponding original PCAP data.")
    print("Do not yet make window packet counts, training labels, or final ML data.")
    print("=== END ===")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, default=100000,
                        help="Read first N data rows only (default 100000, max 500000)")
    parser.add_argument("--csv", default=None,
                        help="Optional explicit CICAPT CSV path")
    args = parser.parse_args()
    if not (1 <= args.sample <= 500000):
        parser.error("--sample must be between 1 and 500000")
    project_root = Path(__file__).resolve().parent.parent
    default = project_root / "data" / "raw" / "cicapt_IIOT_phase2_NetworkData.csv"
    path = Path(args.csv) if args.csv else default
    try:
        inspect(path, args.sample)
    except (OSError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")


if __name__ == "__main__":
    main()
