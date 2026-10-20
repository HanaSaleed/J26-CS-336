#!/usr/bin/env python3
"""J26-CS-336 | CICAPT provisional positive-flow split v2 (read-only input).

Reads only reports/cicapt_positive_flow_split_v1.csv (46 grouped positive flows).
Does NOT access the 9.5-million-row raw CSV or inspect reserved evaluation
features/outcomes. Does NOT train or assign benign-only groups.

Why v2: v1's positive holdout consisted of a single flow and a single attack
category. v2 minimizes class-row imbalance *subject to* positive holdouts that
contain multiple flow keys and multiple attack categories. All source-provided
attack categories must appear in training. Rare single-flow categories remain
train-only. Extremely large individual positive flows (>15% of all positive
observations) are kept in training to avoid a one-flow-dominated holdout.
These are design choices, NOT independent APT-campaign evaluation.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

SEED = 20261019
TARGET = {"train": 0.70, "validation": 0.15, "test": 0.15}
PARTS = tuple(TARGET)
SOURCE = Path("reports/cicapt_positive_flow_split_v1.csv")
OUTPUT_JSON = Path("reports/cicapt_flow_split_plan_v2.json")
OUTPUT_CSV = Path("reports/cicapt_positive_flow_split_v2.csv")


def load_groups(path: Path):
    result = {}
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        necessary = {"canonical_flow_key", "attack_records", "category_counts_json", "utc_day_counts_json"}
        missing = necessary - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing group columns: {sorted(missing)}")
        for row in reader:
            key = row["canonical_flow_key"]
            if key in result:
                raise ValueError(f"Duplicate positive flow key: {key}")
            categories = {k: int(v) for k, v in json.loads(row["category_counts_json"]).items()}
            days = {k: int(v) for k, v in json.loads(row["utc_day_counts_json"]).items()}
            n = int(row["attack_records"])
            if n < 1 or sum(categories.values()) != n or sum(days.values()) != n:
                raise ValueError(f"Invalid per-group counts for {key}")
            result[key] = {"records": n, "categories": categories, "days": days}
    if not result:
        raise ValueError("No positive flows in source")
    return result


def describe(assignments, groups):
    totals = Counter()
    group_counts = Counter()
    cats = {part: Counter() for part in PARTS}
    days = {part: Counter() for part in PARTS}
    largest = Counter()
    for key, part in assignments.items():
        data = groups[key]
        n = data["records"]
        totals[part] += n
        group_counts[part] += 1
        cats[part].update(data["categories"])
        days[part].update(data["days"])
        largest[part] = max(largest[part], n)
    return totals, group_counts, cats, days, largest


def score(assignments, groups, total):
    counts, flows, cats, days, largest = describe(assignments, groups)
    penalty = 0.0
    for part in PARTS:
        deviation = (counts[part] / total - TARGET[part]) / TARGET[part]
        penalty += deviation * deviation
    for part in ("validation", "test"):
        # A one-flow / one-category holdout was the v1 failure mode.
        if flows[part] < 3:
            penalty += 50 * (3 - flows[part]) ** 2
        if len(cats[part]) < 3:
            penalty += 50 * (3 - len(cats[part])) ** 2
        if counts[part] == 0:
            penalty += 1000
        elif largest[part] / counts[part] > 0.5:
            penalty += 100 * (largest[part] / counts[part] - 0.5) ** 2
    return penalty


def plan(groups, attempts=30000):
    total = sum(data["records"] for data in groups.values())
    by_category = defaultdict(set)
    for key, data in groups.items():
        for category in data["categories"]:
            by_category[category].add(key)

    reserved = set()
    reasons = defaultdict(set)
    for category, keys in by_category.items():
        if len(keys) == 1:
            selected = next(iter(keys))
            reserved.add(selected)
            reasons[selected].add("only_flow_for_category")

    # Avoid a massive, single-flow test portion such as v1's 192-record group.
    oversized = {k for k, v in groups.items() if v["records"] / total > 0.15}
    for key in oversized:
        reserved.add(key)
        reasons[key].add("individual_flow_exceeds_15pct_positive_records")

    for category in sorted(by_category, key=lambda t: (len(by_category[t]), t)):
        if reserved & by_category[category]:
            continue
        chosen = min(by_category[category], key=lambda k: (groups[k]["records"], k))
        reserved.add(chosen)
        reasons[chosen].add("reserve_training_category")

    eligible = sorted(k for k in groups if k not in reserved)
    base_count = sum(groups[k]["records"] for k in reserved)
    if len(eligible) < 6:
        raise ValueError(f"Only {len(eligible)} nonreserved flow groups: insufficient for 3+ flows in both holdouts")

    rng = random.Random(SEED)
    remaining_count = total - base_count
    weights = {p: max(0.001, TARGET[p] * total - (base_count if p == "train" else 0)) for p in PARTS}
    weight_sum = sum(weights.values())
    probabilities = [weights[p] / weight_sum for p in PARTS]

    best = None
    best_score = float("inf")
    for iteration in range(attempts):
        assignments = {key: "train" for key in reserved}
        for key in eligible:
            assignments[key] = rng.choices(PARTS, weights=probabilities, k=1)[0]
        current = score(assignments, groups, total)
        if current < best_score:
            best_score = current
            best = dict(assignments)
            if best_score < 0.008:
                break

    if best is None:
        raise ValueError("Could not create a candidate assignment")
    totals, flow_counts, categories, days, largest = describe(best, groups)
    acceptable = all(flow_counts[p] >= 3 and len(categories[p]) >= 3 and
                     largest[p] <= totals[p] / 2 for p in ("validation", "test"))
    if not acceptable:
        raise ValueError("Could not meet minimum holdout diversity; do not publish v2. Review category support and split policy.")
    if set(by_category) != set(categories["train"]):
        raise AssertionError("Training does not cover all positive categories")
    if len(best) != len(groups):
        raise AssertionError("Some positive flow keys were not assigned")

    result = {
        "version": "cicapt_flow_v2_PROVISIONAL",
        "source": str(SOURCE),
        "design_seed": SEED,
        "status": "POSITIVE-FLOW ASSIGNMENTS ONLY; RAW CSV AND BENIGN FLOWS NOT PARTITIONED",
        "total_positive_observations": total,
        "positive_flow_groups": len(groups),
        "distinct_attack_categories": len(by_category),
        "single_positive_flow_categories": sorted(t for t, keys in by_category.items() if len(keys) == 1),
        "reserved_training_positive_flows": len(reserved),
        "oversized_positive_flow_keys_reserved_in_training": sorted(oversized),
        "target_positive_proportions": TARGET,
        "actual_positive_counts": dict(totals),
        "actual_positive_group_counts": dict(flow_counts),
        "actual_positive_category_counts": {p: len(categories[p]) for p in PARTS},
        "positive_records_by_category": {p: dict(sorted(categories[p].items())) for p in PARTS},
        "positive_records_by_utc_day": {p: dict(sorted(days[p].items())) for p in PARTS},
        "largest_positive_group_in_partition": dict(largest),
        "score": best_score,
        "notes": [
            "Positive-only counts do not describe final train/validation/test class balance.",
            "Benign records sharing a positive 5-tuple must follow that positive group's assignment.",
            "Benign-only groups need their own reproducible assignment and verification.",
            "Train retains all attack category names but single-flow categories cannot support heldout evaluation.",
            "Category-aware split design is not evidence of independent attack campaigns or generalization.",
            "Port/IP shortcut and TCP-flag ablations and independent lab evaluation remain essential.",
            "Do not use test holdout for model/feature selection after freeze.",
        ],
    }
    return best, reserved, reasons, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=SOURCE)
    parser.add_argument("--out-json", type=Path, default=OUTPUT_JSON)
    parser.add_argument("--out-csv", type=Path, default=OUTPUT_CSV)
    parser.add_argument("--attempts", type=int, default=30000)
    args = parser.parse_args()
    if not (1 <= args.attempts <= 100000):
        parser.error("--attempts must be between 1 and 100000")
    if args.out_json.exists() or args.out_csv.exists():
        parser.error("v2 output already exists. Will not overwrite: inspect existing reports first.")
    if not args.input.is_file():
        parser.error(f"Missing v1 flow report: {args.input}")

    groups = load_groups(args.input)
    try:
        assignments, reserved, reasons, summary = plan(groups, args.attempts)
    except ValueError as exc:
        parser.error(str(exc))
    for path in (args.out_json, args.out_csv):
        path.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["canonical_flow_key", "proposed_split", "attack_records", "category_counts_json", "utc_day_counts_json", "reserved_train_reasons"])
        for key in sorted(groups):
            data = groups[key]
            writer.writerow([key, assignments[key], data["records"],
                             json.dumps(data["categories"], sort_keys=True),
                             json.dumps(data["days"], sort_keys=True),
                             ";".join(sorted(reasons[key]))])
    with args.out_json.open("x", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)

    print("=== CICAPT V2 POSITIVE-FLOW SPLIT CANDIDATE ===")
    print(f"Positive observations: {summary['total_positive_observations']:,}; groups: {summary['positive_flow_groups']}; category names: {summary['distinct_attack_categories']}")
    print(f"Single-flow categories: {len(summary['single_positive_flow_categories'])}; mandatory training flows: {len(reserved)}")
    print("V1 comparison: train 666 / 39 flows / 25 categories; validation 146 / 6 / 5; test 192 / 1 / 1")
    for p in PARTS:
        print(f"{p:10}: {summary['actual_positive_counts'].get(p, 0):4d} attack records; "
              f"{summary['actual_positive_group_counts'].get(p, 0):2d} flows; "
              f"{summary['actual_positive_category_counts'][p]:2d} categories")
    print("NOTE: PROVISIONAL positive-only plan. Benign flows not yet assigned. No raw source rescanned.")
    print(f"Plan: {args.out_json}")
    print(f"Positive group mapping: {args.out_csv}")

if __name__ == "__main__":
    main()
