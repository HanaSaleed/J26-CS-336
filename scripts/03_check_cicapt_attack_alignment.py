#!/usr/bin/env python3
r"""Phase 5 diagnostic: inspect CICAPT labels, metadata timestamps, and audit ranges.

Read-only. Examines only the first N Phase 2 CSV rows (default 100,000).
Never modifies source CSVs or labels, and never infers packet-level ground truth
from timestamp proximity alone.

Save to: <project>/scripts/03_check_cicapt_attack_alignment.py
Run from project:
  .\.venv\Scripts\python.exe .\scripts\03_check_cicapt_attack_alignment.py --sample 100000
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def utc(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def num(s: object) -> float | None:
    try:
        return float(str(s).strip())
    except (ValueError, TypeError):
        return None


def load_metadata(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f"Attack metadata not found: {path}")
    with path.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    events = []
    offsets = Counter()
    for row in rows:
        ts = num(row.get("Time of Attack"))
        if ts is None:
            continue
        events.append({
            "ts": ts,
            "tactic": row.get("Tactic Name", ""),
            "technique": row.get("Technique Name", ""),
        })
        readable = row.get("readable_time", "").strip()
        try:
            human = datetime.strptime(readable, "%Y-%m-%d %H:%M:%S")
            offset = (datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None) - human).total_seconds() / 3600
            offsets[round(offset, 3)] += 1
        except (ValueError, OverflowError):
            pass
    if not events:
        raise ValueError(f"No usable 'Time of Attack' values in {path}")
    events.sort(key=lambda e: e["ts"])
    print("=== ATTACK METADATA ===")
    print(f"Events: {len(events)}; distinct timestamps: {len(set(e['ts'] for e in events))}")
    print(f"First: {utc(events[0]['ts'])}")
    print(f"Last:  {utc(events[-1]['ts'])}")
    print(f"Numeric UTC timestamp minus readable_time (hours): {dict(offsets)}")
    print("Note: a constant difference suggests a display time-zone offset; it does not prove source-clock alignment.")
    return events


def show_full_audit(root: Path, events: list[dict]) -> None:
    print("\n=== PREVIOUS FULL AUDIT RANGES (NO CSV RESCAN) ===")
    audit_candidates = sorted((root / "reports").glob("network_audit_*.json"), reverse=True)
    chosen = None
    for path in audit_candidates:
        try:
            with path.open(encoding="utf-8") as f:
                obj = json.load(f)
        except (OSError, ValueError):
            continue
        if all(entry.get("scope") == "full_file" and entry.get("complete_to_eof")
               for entry in obj.get("files", [])):
            chosen = (path, obj)
            break
    if chosen is None:
        print("No completed full-file audit found in reports/. Skipping this comparison.")
        return
    path, audit = chosen
    print("Source:", path.name)
    first_attack, last_attack = events[0]["ts"], events[-1]["ts"]
    for entry in audit.get("files", []):
        name = Path(entry.get("file", "unknown")).name
        checks = entry.get("numeric_checks", {}).get("ts", {})
        lo, hi = num(checks.get("minimum")), num(checks.get("maximum"))
        if lo is None or hi is None:
            print(f"{name}: no timestamp range in audit")
            continue
        intersects = (lo <= last_attack and hi >= first_attack)
        print(f"{name}: {utc(lo)} -> {utc(hi)}; overlaps metadata range: {intersects}")
    print("An overlapping *range* does NOT establish packet-to-event matching.")


def inspect_phase2(path: Path, events: list[dict], limit: int, max_examples: int) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Phase 2 CSV not found: {path}")
    print(f"\n=== PHASE 2 FIRST {limit:,} ROWS ONLY ===")
    print("Source:", path.name)
    counts = Counter()
    positive = []
    within_range = 0
    samples = 0
    min_event, max_event = events[0]["ts"], events[-1]["ts"]
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"ts", "label", "subLabel", "subLabelCat"}
        absent = required - set(reader.fieldnames or [])
        if absent:
            raise ValueError(f"Missing columns in Phase 2 CSV: {sorted(absent)}")
        for row in reader:
            if samples >= limit:
                break
            samples += 1
            label = (row.get("label") or "").strip()
            counts[label] += 1
            ts = num(row.get("ts"))
            if ts is not None and min_event <= ts <= max_event:
                within_range += 1
            if label == "1" and ts is not None:
                event = min(events, key=lambda e: abs(e["ts"] - ts))
                positive.append((samples, ts, row.get("subLabel", ""), row.get("subLabelCat", ""), event))

    print(f"Rows examined: {samples:,}")
    print("Label counts:", dict(counts))
    print(f"Rows within metadata's broad attack-time range: {within_range:,}")
    print(f"Labeled attack rows in sample: {len(positive):,}")
    print(f"\nFirst {min(max_examples, len(positive))} labeled attack rows with *nearest* metadata event:")
    for i, (row_num, ts, tactic, technique, ev) in enumerate(positive[:max_examples], start=1):
        delta = ts - ev["ts"]
        print(f"{i:02d}. CSV row {row_num:,} | {utc(ts)}")
        print(f"    CSV tactic={tactic!r} | CSV technique={technique!r}")
        print(f"    Nearest metadata: {utc(ev['ts'])} | {ev['tactic']!r} / {ev['technique']!r}")
        print(f"    Timestamp difference (CSV - event): {delta:+.3f} seconds")
        agrees = (tactic.strip().casefold() == ev["tactic"].strip().casefold() and
                  technique.strip().casefold() == ev["technique"].strip().casefold())
        print(f"    Text labels agree with nearest event: {agrees}")
    print("\nIMPORTANT: Nearest timestamp and matching text do NOT prove the event caused that packet.")
    print("A source-provided packet/event mapping, verified event interval, or reproducible experiment is needed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="CICAPT Phase 2 attack-label/time probe, read-only")
    parser.add_argument("--sample", type=int, default=100000, help="First N Phase 2 CSV rows (1..100000)")
    parser.add_argument("--show", type=int, default=10, help="Attack examples to print (1..25)")
    args = parser.parse_args()
    if not 1 <= args.sample <= 100000:
        parser.error("--sample must be in 1..100000")
    if not 1 <= args.show <= 25:
        parser.error("--show must be in 1..25")

    root = Path(__file__).resolve().parent.parent
    print("CICAPT label and time alignment probe (READ ONLY)")
    print("Project root:", root)
    events = load_metadata(root / "data" / "metadata" / "cicapt" / "attack_info.csv")
    show_full_audit(root, events)
    inspect_phase2(root / "data" / "raw" / "cicapt_IIOT_phase2_NetworkData.csv",
                   events, args.sample, args.show)


if __name__ == "__main__":
    main()
