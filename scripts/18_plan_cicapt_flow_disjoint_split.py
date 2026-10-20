#!/usr/bin/env python3
"""J26-CS-336 | CICAPT Phase 2 provisional, flow-disjoint split design.

Reads ONLY the 1,004-row, previously saved positive observation report. It does
NOT scan/rewrite the 4GB Phase 2 data; does NOT split it, train, or evaluate.

This produces a candidate policy/positive-flow assignment for inspection:
  reports/cicapt_flow_split_plan_v1.json
  reports/cicapt_positive_flow_split_v1.csv

A flow is the bidirectional canonical (IP, port, IP, port, protocol) 5-tuple.
An event/flow may have multiple technique names. Single-flow-supported
techniques are kept in training, and each observed category has at least
one positive flow in training, to avoid an unseen-only training category.
Benign-only flow assignment is a PROPOSED deterministic hash policy; not yet
applied, so benign split balance and session isolation are not verified.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT = Path('reports/cicapt_attack_temporal_candidates_20261019T170646_912515Z.csv')
SEED = 'J26-CS-336|CICAPT|flow-v1'
TARGET = {'train': 0.70, 'validation': 0.15, 'test': 0.15}
REQUIRED = {
    'source_ip', 'destination_ip', 'source_port', 'destination_port',
    'protocol_as_stored', 'dataset_subLabelCat', 'dataset_label',
    'timestamp_epoch',
}


def flow_key(row):
    src = str(ipaddress.ip_address(row['source_ip'].strip()))
    dst = str(ipaddress.ip_address(row['destination_ip'].strip()))
    sport = int(row['source_port'])
    dport = int(row['destination_port'])
    proto = int(row['protocol_as_stored'])
    if not (0 <= sport <= 65535 and 0 <= dport <= 65535 and 0 <= proto <= 255):
        raise ValueError('Invalid port/protocol')
    endpoints = sorted(((src, sport), (dst, dport)))
    # json array encoding avoids ambiguous separators in IP addresses
    return json.dumps([proto, endpoints], separators=(',', ':'))


def stable_int(value):
    return int.from_bytes(hashlib.blake2b(
        (SEED + '|' + value).encode('utf-8'), digest_size=8
    ).digest(), 'big')


def benign_flow_partition(key):
    """Proposed future assignment for flows without any attack labels."""
    fraction = stable_int(key) / 2**64
    if fraction < 0.70:
        return 'train'
    if fraction < 0.85:
        return 'validation'
    return 'test'


def create_plan(source: Path, report_dir: Path):
    if not source.is_file():
        raise FileNotFoundError(source)
    groups = defaultdict(lambda: {'rows': 0, 'techniques': Counter(), 'days': Counter()})
    total = 0
    with source.open('r', encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f'Missing report fields: {sorted(missing)}')
        for row in reader:
            if row['dataset_label'].strip() != '1':
                raise ValueError('Report must contain ONLY source-labeled attacks')
            key = flow_key(row)
            name = row['dataset_subLabelCat'].strip()
            if not name:
                raise ValueError('Blank technique category')
            day = datetime.fromtimestamp(float(row['timestamp_epoch']), timezone.utc).strftime('%Y-%m-%d')
            groups[key]['rows'] += 1
            groups[key]['techniques'][name] += 1
            groups[key]['days'][day] += 1
            total += 1
    if not total or not groups:
        raise ValueError('Empty positive observation report')

    technique_to_groups = defaultdict(set)
    for key, data in groups.items():
        for technique in data['techniques']:
            technique_to_groups[technique].add(key)
    singleton_techniques = sorted(t for t, keys in technique_to_groups.items() if len(keys) == 1)
    # Reserve at least one group for each category in training; if a category
    # appears on just one flow, that entire flow must be train-only.
    force_train = set()
    for category in sorted(technique_to_groups, key=lambda t: (len(technique_to_groups[t]), t)):
        if technique_to_groups[category] & force_train:
            continue
        candidates = technique_to_groups[category]
        chosen = min(candidates, key=lambda k: (
            -sum(1 for t in groups[k]['techniques'] if not (technique_to_groups[t] & force_train)),
            groups[k]['rows'], stable_int(k)
        ))
        force_train.add(chosen)
    assignments = {key: 'train' for key in force_train}
    counts = Counter({'train': sum(groups[k]['rows'] for k in force_train), 'validation': 0, 'test': 0})
    target_rows = {part: total * proportion for part, proportion in TARGET.items()}
    remaining = sorted((k for k in groups if k not in force_train),
                       key=lambda k: (-groups[k]['rows'], stable_int(k)))
    for key in remaining:
        n = groups[key]['rows']
        def cost(part):
            # Minimize deviation from row-share targets after each assignment.
            hypothetical = dict(counts)
            hypothetical[part] = hypothetical.get(part, 0) + n
            return sum(((hypothetical[p] - target_rows[p]) ** 2) / max(1, target_rows[p])
                       for p in ('train', 'validation', 'test'))
        choice = min(('train', 'validation', 'test'), key=lambda p: (cost(p), stable_int(key + p)))
        assignments[key] = choice
        counts[choice] += n

    by_part_technique = defaultdict(Counter)
    by_part_day = defaultdict(Counter)
    group_counts = Counter(assignments.values())
    for key, data in groups.items():
        part = assignments[key]
        by_part_technique[part].update(data['techniques'])
        by_part_day[part].update(data['days'])

    plan = {
        'project': 'J26-CS-336',
        'version': 'cicapt_flow_v1_PROVISIONAL',
        'source_positive_report': str(source),
        'scope': 'CICAPT IIoT Phase2 only; attack-labeled observations from original labels',
        'positive_observations': total,
        'positive_bidirectional_5tuple_groups': len(groups),
        'distinct_attack_categories': len(technique_to_groups),
        'categories_with_only_one_positive_flow_group': singleton_techniques,
        'target_fraction_of_positive_records': TARGET,
        'positive_record_counts_by_split': {p: counts[p] for p in TARGET},
        'positive_group_counts_by_split': {p: group_counts[p] for p in TARGET},
        'positive_category_records_by_split': {p: dict(sorted(by_part_technique[p].items())) for p in TARGET},
        'positive_records_by_utc_day_and_split': {p: dict(sorted(by_part_day[p].items())) for p in TARGET},
        'grouping': 'canonical bidirectional [ip_protocol, [[ip,port],[ip,port]]] key',
        'priority': 'at least one group per observed attack category reserved in training; other groups greedy positive-row balance',
        'future_benign_only_flow_assignment': {
            'applied': False,
            'description': 'Use SAME canonical flow key; groups containing positives always use explicit positive mapping. Otherwise stable blake2b(SEED|key) fraction: train <.70, validation <.85, test otherwise.',
            'seed': SEED,
        },
        'status': 'PROPOSED ASSIGNMENT - NOT YET A MATERIALIZED SPLIT OR HELD-OUT EVALUATION',
        'caveats': [
            'Flow-disjoint does not mean campaign-disjoint: this is one known CICAPT experiment.',
            'Attack categories with a single positive flow cannot appear across all train/validation/test splits.',
            'No benign flow assignments verified yet. Proportions apply only to 1,004 source-positive records.',
            'A five-tuple may represent recurrent connections, not one independently verified attack event.',
            'Provisional split is not a claim of real-world generalization or APT attribution.',
            'No raw CSV feature values or held-out test outcomes are examined by this script.',
        ],
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    json_dest = report_dir / 'cicapt_flow_split_plan_v1.json'
    csv_dest = report_dir / 'cicapt_positive_flow_split_v1.csv'
    if json_dest.exists() or csv_dest.exists():
        raise FileExistsError('v1 plan already exists; do not overwrite a frozen split. Inspect existing outputs first.')
    with csv_dest.open('x', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['canonical_flow_key', 'proposed_split', 'attack_records', 'category_counts_json', 'utc_day_counts_json', 'reserved_for_train_category_coverage'])
        for key in sorted(groups):
            data = groups[key]
            writer.writerow([key, assignments[key], data['rows'],
                             json.dumps(dict(sorted(data['techniques'].items())), separators=(',', ':')),
                             json.dumps(dict(sorted(data['days'].items())), separators=(',', ':')),
                             int(key in force_train)])
    with json_dest.open('x', encoding='utf-8') as handle:
        json.dump(plan, handle, indent=2, ensure_ascii=False)

    print('=== CICAPT PROVISIONAL FLOW-DISJOINT SPLIT PLAN ===')
    print(f'Attack observations: {total:,}; positive flow groups: {len(groups)}; categories: {len(technique_to_groups)}')
    print(f'Categories supported by ONE positive flow group: {len(singleton_techniques)}')
    print('Positive records by proposed split (not complete dataset counts):')
    for p in TARGET:
        print(f'  {p:10s} {counts[p]:4d} ({counts[p] / total * 100:.1f}%)   flow groups={group_counts[p]:2d}   observed categories={len(by_part_technique[p]):2d}')
    print('Categories missing from training:', sorted(set(technique_to_groups) - set(by_part_technique['train'])))
    print('NOTE: This is NOT a train/test data split yet. Benign flows have not been assigned.')
    print(f'Plan: {json_dest}')
    print(f'Positive group mapping: {csv_dest}')
    print('Source report and original Phase2 CSV were not modified or rescanned.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positive-report', type=Path, default=DEFAULT)
    parser.add_argument('--report-dir', type=Path, default=Path('reports'))
    args = parser.parse_args()
    try:
        create_plan(args.positive_report, args.report_dir)
    except (ValueError, OSError, csv.Error) as exc:
        parser.exit(1, f'STOPPED: {exc}\n')


if __name__ == '__main__':
    main()
