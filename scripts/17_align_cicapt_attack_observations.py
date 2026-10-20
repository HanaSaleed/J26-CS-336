"""J26-CS-336 | Read-only CICAPT Phase 2 label/Caldera temporal-candidate audit.

Produces an evidence CSV of ALL attack-labeled exported observations (not validated
packets), plus a JSON summary.  It NEVER changes labels, trains a model,
opens the ToN-IoT held-out test partition, or claims causal attribution.

From D:\\IIoT-APT-Research:
  .\\.venv\\Scripts\\python.exe .\\scripts\\17_align_cicapt_attack_observations.py --limit 0
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

FIELDS = (
    "ts", "label", "subLabel", "subLabelCat", "Source IP", "Destination IP",
    "Source Port", "Destination Port", "Protocol Type"
)


def epoch(raw, field):
    try:
        value = float(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{field}: not numeric: {raw!r}") from exc
    if not (math.isfinite(value) and value > 0):
        raise ValueError(f"{field}: not a positive finite epoch: {raw!r}")
    try:
        datetime.fromtimestamp(value, tz=timezone.utc)
    except (ValueError, OSError, OverflowError) as exc:
        raise ValueError(f"{field}: timestamp outside supported range: {raw!r}") from exc
    return value


def utc(value):
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="milliseconds")


def load_metadata(path):
    by_name = defaultdict(list)
    rows = []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not {"Time of Attack", "Tactic Name", "Technique Name"}.issubset(reader.fieldnames):
            raise ValueError("Attack metadata requires Time of Attack, Tactic Name and Technique Name")
        for ix, row in enumerate(reader, 1):
            ts = epoch(row["Time of Attack"], f"attack_info.csv row {ix} Time of Attack")
            technique = row["Technique Name"].strip()
            if not technique:
                raise ValueError(f"Missing metadata technique at row {ix}")
            event = {"metadata_row": ix, "time_epoch": ts, "utc": utc(ts),
                     "technique": technique, "tactic": row["Tactic Name"].strip(),
                     "pid": row.get("PID", "").strip()}
            rows.append(event)
            by_name[technique.casefold()].append(event)
    for matches in by_name.values():
        matches.sort(key=lambda item: (item["time_epoch"], item["metadata_row"]))
    return rows, by_name


def audit(csv_path, metadata_path, output_dir, limit=0):
    if limit < 0:
        raise ValueError("--limit cannot be negative")
    meta_rows, by_name = load_metadata(metadata_path)
    before = (csv_path.stat().st_size, csv_path.stat().st_mtime_ns)
    meta_before = (metadata_path.stat().st_size, metadata_path.stat().st_mtime_ns)
    start = time.monotonic()
    results = []
    label_counts = Counter()
    inspected = 0
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not set(FIELDS).issubset(reader.fieldnames):
            raise ValueError(f"CICAPT CSV is missing columns: {sorted(set(FIELDS) - set(reader.fieldnames or []))}")
        for ix, row in enumerate(reader, 1):
            if limit and ix > limit:
                break
            inspected += 1
            label = row["label"].strip()
            label_counts[label] += 1
            if label not in {"0", "1"}:
                raise ValueError(f"Unexpected label at CSV data row {ix}: {label!r}")
            if label != "1":
                if inspected % 1_000_000 == 0:
                    print(f"  scanned {inspected:,}; attack labeled {len(results):,}", flush=True)
                continue
            t = epoch(row["ts"], f"CSV row {ix} ts")
            name = row["subLabelCat"].strip()
            candidates = by_name.get(name.casefold(), [])
            near = min(candidates, key=lambda item: (abs(t - item["time_epoch"]), item["metadata_row"])) if candidates else None
            signed = t - near["time_epoch"] if near else None
            results.append({
                "csv_data_row": ix, "timestamp_epoch": row["ts"],
                "timestamp_utc_if_epoch_seconds": utc(t),
                "source_ip": row["Source IP"], "destination_ip": row["Destination IP"],
                "source_port": row["Source Port"], "destination_port": row["Destination Port"],
                "protocol_as_stored": row["Protocol Type"],
                "dataset_label": label, "dataset_subLabel": row["subLabel"], "dataset_subLabelCat": name,
                "nearest_exact_name_metadata_row": near["metadata_row"] if near else "",
                "nearest_exact_name_metadata_tactic": near["tactic"] if near else "",
                "nearest_exact_name_metadata_utc": near["utc"] if near else "",
                "signed_seconds_from_metadata_event": round(signed, 6) if signed is not None else "",
                "abs_seconds_from_metadata_event": round(abs(signed), 6) if signed is not None else "",
                "within_30_seconds": bool(abs(signed) <= 30) if signed is not None else False,
                "within_120_seconds": bool(abs(signed) <= 120) if signed is not None else False,
                "within_300_seconds": bool(abs(signed) <= 300) if signed is not None else False,
                "matching_method": "nearest_exact_technique_name_only_not_verified_causation",
            })
            if inspected % 1_000_000 == 0:
                print(f"  scanned {inspected:,}; attack labeled {len(results):,}", flush=True)
    after = (csv_path.stat().st_size, csv_path.stat().st_mtime_ns)
    meta_after = (metadata_path.stat().st_size, metadata_path.stat().st_mtime_ns)
    if before != after or meta_before != meta_after:
        raise RuntimeError("Source file size/mtime changed during scan. No report saved")
    results.sort(key=lambda r: (float(r["timestamp_epoch"]), r["csv_data_row"]))
    by_category = {}
    for category in sorted({r["dataset_subLabelCat"] for r in results}):
        group = [r for r in results if r["dataset_subLabelCat"] == category]
        by_category[category] = {"attack_labeled_records": len(group),
                                 "within_30_seconds": sum(r["within_30_seconds"] for r in group),
                                 "within_120_seconds": sum(r["within_120_seconds"] for r in group),
                                 "within_300_seconds": sum(r["within_300_seconds"] for r in group)}
    report = {
        "project_id": "J26-CS-336", "purpose": "CICAPT Phase 2 exploratory temporal candidates against Caldera attack_info",
        "source_csv": str(csv_path.resolve()), "metadata": str(metadata_path.resolve()),
        "scope": "full_file" if not limit else f"first_{limit}_rows", "records_scanned": inspected,
        "binary_labels": dict(sorted(label_counts.items())), "attack_labeled_records": len(results),
        "metadata_event_count": len(meta_rows), "metadata_unique_technique_names": len(by_name),
        "network_attack_category_count": len(by_category),
        "nearest_same_name_within_seconds": {str(th): sum(r[f"within_{th}_seconds"] for r in results)
                                             for th in (30, 120, 300)},
        "no_exact_name_metadata_candidates": sum(not r["nearest_exact_name_metadata_row"] for r in results),
        "by_network_category": by_category,
        "earliest_attack_labeled_utc": results[0]["timestamp_utc_if_epoch_seconds"] if results else None,
        "latest_attack_labeled_utc": results[-1]["timestamp_utc_if_epoch_seconds"] if results else None,
        "sources_unchanged_size_mtime": True,
        "elapsed_seconds": round(time.monotonic()-start, 2),
        "limitations": [
            "Temporal proximity plus an exact category name is NOT ground-truth event attribution.",
            "Nearest-match algorithm reuses metadata events; no one-to-one event pairing is inferred.",
            "No timestamp shift is applied or inferred. NS-3 capture timing must be verified independently.",
            "Exports are network CSV observations; one row has not been verified to equal one original packet.",
            "Source labels and category names are retained as evidence; never put them into model predictors.",
            "This reads ONLY the CICAPT Phase 2 CSV and attack_info.csv; no ML training or test data use.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    csv_out = output_dir / f"cicapt_attack_temporal_candidates_{stamp}.csv"
    json_out = output_dir / f"cicapt_attack_temporal_candidates_{stamp}.json"
    cols = (list(results[0].keys()) if results else [
        "csv_data_row", "timestamp_epoch", "timestamp_utc_if_epoch_seconds", "dataset_label", "dataset_subLabelCat"])
    with csv_out.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=cols)
        writer.writeheader()
        writer.writerows(results)
    try:
        with json_out.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
    except BaseException:
        csv_out.unlink(missing_ok=True)
        raise
    print("=== CICAPT PHASE 2 TEMPORAL CANDIDATES (READ-ONLY AUDIT) ===")
    print(f"CSV records scanned: {inspected:,}")
    print(f"Attack-labeled records: {len(results):,}")
    print(f"Caldera metadata events: {len(meta_rows)}")
    print("Attack-labeled records with a same-name candidate within ±seconds:")
    for th in (30,120,300):
        print(f"  ±{th}s: {report['nearest_same_name_within_seconds'][str(th)]}")
    print("Without any exact-name metadata candidate:", report["no_exact_name_metadata_candidates"])
    print("Time-sorted attack observation CSV:", csv_out)
    print("Summary JSON:", json_out)
    print("Sources unchanged. No labeling, training, causal matching, or model evaluation performed.")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=Path("data/raw/cicapt_IIOT_phase2_NetworkData.csv"))
    parser.add_argument("--metadata", type=Path, default=Path("data/metadata/cicapt/attack_info.csv"))
    parser.add_argument("--out-dir", type=Path, default=Path("reports"))
    parser.add_argument("--limit", type=int, default=0, help="0 = full Phase 2 file; positive = first N CSV records")
    args = parser.parse_args()
    try:
        audit(args.csv, args.metadata, args.out_dir, args.limit)
    except (OSError, ValueError, RuntimeError, csv.Error) as exc:
        parser.exit(1, f"STOPPED: {exc}\n")


if __name__ == "__main__":
    main()
