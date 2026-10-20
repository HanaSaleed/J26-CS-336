#!/usr/bin/env python3
"""J26-CS-336 / Checkpoint 03 — CICAPT Phase 2 label/timestamp audit.

Read-only inspection of the original Phase 2 CSV. Does not train a model,
change labels, assert that CSV rows are packets, or access ToN-IoT test data.

PowerShell (run from D:\\IIoT-APT-Research):
  .\\.venv\\Scripts\\python.exe .\\scripts\\16_audit_cicapt_phase2_attack_timeline.py --limit 100000
  .\\.venv\\Scripts\\python.exe .\\scripts\\16_audit_cicapt_phase2_attack_timeline.py --limit 0

0 means scan to end-of-file. Each run saves a uniquely timestamped JSON report.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = (
    "ts", "label", "subLabel", "subLabelCat",
    "Source IP", "Destination IP", "Source Port", "Destination Port",
    "Protocol Type",
)


def utc_or_note(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="milliseconds")
    except (ValueError, OverflowError, OSError):
        return "outside_supported_datetime_range"


def top_counts(counter: Counter, n: int = 12) -> list[dict]:
    return [{"value": str(value), "count": count} for value, count in counter.most_common(n)]


def summarize(csv_path: Path, limit: int, verbose: bool = True) -> dict:
    started = time.monotonic()
    original_stat = csv_path.stat()
    labels = Counter()
    sublabels = Counter()
    subcats = Counter()
    attack_pairs = Counter()
    attack_ports = Counter()
    attack_protocols = Counter()
    attack_sources = Counter()
    timestamp_missing = 0
    timestamp_invalid = 0
    previous_timestamp = None
    first_ts = last_ts = minimum_ts = maximum_ts = None
    decreases = equals = 0
    decrease_examples = []
    attack_min_ts = attack_max_ts = None
    attack_examples = []
    prior_rows = deque(maxlen=2)
    rows = 0
    source_fields = None

    with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream, restkey="__EXTRA_CELLS__", restval=None)
        source_fields = reader.fieldnames
        if not source_fields:
            raise ValueError("CSV header is missing")
        if len(source_fields) != len(set(source_fields)):
            raise ValueError("Duplicate column names in source CSV")
        missing = sorted(set(REQUIRED) - set(source_fields))
        if missing:
            raise ValueError(f"Required columns missing: {missing}")

        for row in reader:
            if limit and rows >= limit:
                break
            rows += 1
            if row.get("__EXTRA_CELLS__") is not None or any(row.get(k) is None for k in REQUIRED):
                raise ValueError(f"Malformed CSV record at data row {rows}; STOP, source untouched")

            label = row["label"].strip()
            if label not in ("0", "1"):
                raise ValueError(f"Unsupported binary label {label!r} at data row {rows}")
            labels[label] += 1

            raw = row["ts"].strip()
            ts = None
            if not raw:
                timestamp_missing += 1
            else:
                try:
                    ts = float(raw)
                except ValueError:
                    timestamp_invalid += 1
                else:
                    if not math.isfinite(ts) or ts <= 0:
                        timestamp_invalid += 1
                        ts = None

            if ts is not None:
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
                minimum_ts = ts if minimum_ts is None else min(minimum_ts, ts)
                maximum_ts = ts if maximum_ts is None else max(maximum_ts, ts)
                if previous_timestamp is not None:
                    if ts < previous_timestamp:
                        decreases += 1
                        if len(decrease_examples) < 8:
                            decrease_examples.append({
                                "csv_data_row": rows,
                                "previous_ts": previous_timestamp,
                                "current_ts": ts,
                                "backward_seconds_if_epoch_seconds": round(previous_timestamp - ts, 6),
                                "previous_utc_if_epoch_seconds": utc_or_note(previous_timestamp),
                                "current_utc_if_epoch_seconds": utc_or_note(ts),
                            })
                    elif ts == previous_timestamp:
                        equals += 1
            # If a timestamp is invalid, do not compare against an older valid record.
            previous_timestamp = ts

            if label == "1":
                sublabels[row["subLabel"].strip()] += 1
                subcats[row["subLabelCat"].strip()] += 1
                source = row["Source IP"].strip()
                dest = row["Destination IP"].strip()
                attack_pairs[(source, dest)] += 1
                attack_sources[source] += 1
                attack_ports[row["Destination Port"].strip()] += 1
                attack_protocols[row["Protocol Type"].strip()] += 1
                if ts is not None:
                    attack_min_ts = ts if attack_min_ts is None else min(attack_min_ts, ts)
                    attack_max_ts = ts if attack_max_ts is None else max(attack_max_ts, ts)
                if len(attack_examples) < 10:
                    attack_examples.append({
                        "csv_data_row": rows,
                        "timestamp_as_stored": row["ts"],
                        "utc_if_epoch_seconds": utc_or_note(ts),
                        "source_ip": source,
                        "destination_ip": dest,
                        "source_port": row["Source Port"].strip(),
                        "destination_port": row["Destination Port"].strip(),
                        "protocol_as_stored": row["Protocol Type"].strip(),
                        "subLabel": row["subLabel"].strip(),
                        "subLabelCat": row["subLabelCat"].strip(),
                        "preceding_data_rows": list(prior_rows),
                    })

            prior_rows.append({"data_row": rows, "label": label,
                               "ts": raw, "source": row["Source IP"].strip(),
                               "destination": row["Destination IP"].strip()})
            if verbose and rows % 1_000_000 == 0:
                print(f"  {rows:,} records | attack-labeled {labels['1']:,} | "
                      f"backward timestamp jumps {decreases:,}", flush=True)

    updated_stat = csv_path.stat()
    result = {
        "research_id": "J26-CS-336",
        "purpose": "CICAPT-IIoT phase 2 attack-label and timestamp audit",
        "source_file": str(csv_path.resolve()),
        "scope": "full_file" if not limit or rows < limit else "first_N_records_only",
        "limit": limit,
        "data_records_read": rows,
        "source_unchanged_size_and_mtime": (
            original_stat.st_size == updated_stat.st_size
            and original_stat.st_mtime_ns == updated_stat.st_mtime_ns
        ),
        "binary_label_counts": dict(sorted(labels.items())),
        "attack_labeled_fraction": round(labels["1"] / rows, 10) if rows else None,
        "timestamp_missing": timestamp_missing,
        "timestamp_invalid": timestamp_invalid,
        "adjacent_timestamp_decreases_in_csv_order": decreases,
        "adjacent_equal_timestamps_in_csv_order": equals,
        "timestamp_range_if_epoch_seconds": {
            "first_file_row_utc": utc_or_note(first_ts),
            "last_file_row_utc": utc_or_note(last_ts),
            "minimum_utc": utc_or_note(minimum_ts),
            "maximum_utc": utc_or_note(maximum_ts),
            "first_attack_labeled_utc": utc_or_note(attack_min_ts),
            "last_attack_labeled_utc": utc_or_note(attack_max_ts),
        },
        "backward_jump_examples": decrease_examples,
        "attack_subLabel_counts": top_counts(sublabels, 50),
        "attack_subLabelCat_counts": top_counts(subcats, 50),
        "attack_source_ip_counts": top_counts(attack_sources),
        "attack_source_destination_pairs": [
            {"source_ip": pair[0], "destination_ip": pair[1], "count": count}
            for pair, count in attack_pairs.most_common(12)
        ],
        "attack_destination_port_counts": top_counts(attack_ports),
        "attack_protocol_counts": top_counts(attack_protocols),
        "first_attack_labeled_examples": attack_examples,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "limitations": [
            "CSV data rows have not been verified to represent individual original packets.",
            "UTC conversions assume ts is Unix epoch seconds; the source timestamp semantics remain to be verified.",
            "Dataset binary labels and sublabels are reported as stored, not independently authenticated.",
            "A group of rows sharing labels/IPs/times is not proof of an APT campaign or MITRE technique.",
            "No training, labeling, filtering, sorting, model prediction or test-set access was performed.",
        ],
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=None,
                        help="Optional source CSV; defaults to data/raw/cicapt_IIOT_phase2_NetworkData.csv")
    parser.add_argument("--limit", type=int, default=100000,
                        help="0 to scan full file; otherwise first N rows; default 100000")
    parser.add_argument("--report-dir", type=Path, default=None,
                        help="Folder to save unique JSON reports; defaults to reports/")
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit must be 0 or a positive number")
    root = Path(__file__).resolve().parents[1]
    source = args.csv or root / "data" / "raw" / "cicapt_IIOT_phase2_NetworkData.csv"
    report_dir = args.report_dir or root / "reports"
    if not source.is_file():
        parser.error(f"Dataset not found: {source}")
    print("=== CICAPT-IIoT PHASE 2 LABEL + TIMESTAMP AUDIT ===", flush=True)
    print("Source (READ ONLY):", source)
    print("Scan:", "FULL CSV" if args.limit == 0 else f"first {args.limit:,} records")
    try:
        result = summarize(source, args.limit)
        if not result["source_unchanged_size_and_mtime"]:
            raise RuntimeError("Source file changed during scan; no report saved")
        report_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        path = report_dir / f"cicapt_phase2_attack_timeline_{stamp}.json"
        with path.open("x", encoding="utf-8") as output:
            json.dump(result, output, indent=2, ensure_ascii=False, allow_nan=False)
    except (OSError, ValueError, RuntimeError, csv.Error) as exc:
        parser.exit(1, f"STOPPED: {exc}\n")

    print("Records:", f"{result['data_records_read']:,}")
    print("Labels:", result["binary_label_counts"])
    print("Attack-labeled fraction:", f"{result['attack_labeled_fraction']:.5%}")
    print("Backward timestamp jumps:", result["adjacent_timestamp_decreases_in_csv_order"])
    print("Timestamp missing/invalid:", result["timestamp_missing"], result["timestamp_invalid"])
    print("Attack subLabel categories:", result["attack_subLabelCat_counts"])
    print("Attack source/destination pairs:", result["attack_source_destination_pairs"][:5])
    print("Duration (s):", result["elapsed_seconds"])
    print("Report:", path)
    print("No source data, labels, model or held-out test data changed.")


if __name__ == "__main__":
    main()
