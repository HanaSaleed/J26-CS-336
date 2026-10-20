#!/usr/bin/env python3
"""J26-CS-336 | CICAPT Phase 2 full-data split preflight for flow-v2 (patched).

READ ONLY on the 9.5-million-row raw CSV and v2 positive-flow assignment.
Outputs one NEW summary JSON; does not materialize train/validation/test CSVs,
modify labels, select features, fit models, or open the ToN-IoT held-out test.

Method:
- Canonical, bidirectional [protocol, [[ip, port], [ip, port]]] flow key,
  identical to script 18 (sort endpoints; JSON compact encoding).
- Non-IP address tokens in benign records are tracked and hashed using a distinct,
  explicit surrogate-key namespace; no records are silently deleted. Attack
  records with non-IP tokens cause STOP (cannot match verified positive plan).
- All rows in one of 46 positive-containing groups follow v2 assignment,
  INCLUDING normal-labeled rows using the same flow key.
- Other (benign-only) flows are assigned via a deterministic BLAKE2b hash:
  seed = J26-CS-336|CICAPT|flow-v1, buckets 70/15/15.
- Hashing balances flow-key probability, NOT necessarily row counts.
- Independent attack campaigns, semantic labels, and packet/PCAP mapping
  remain unverified; the test split must be frozen before model selection.

Run from research root:
  .\\.venv\\Scripts\\python.exe .\\scripts\\20_audit_cicapt_complete_split_v2.py
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

SEED = 'J26-CS-336|CICAPT|flow-v1'  # Keep identical to script 18.
PARTS = ('train', 'validation', 'test')
TARGET = {'train': .70, 'validation': .15, 'test': .15}
RAW = Path('data/raw/cicapt_IIOT_phase2_NetworkData.csv')
POS = Path('reports/cicapt_positive_flow_split_v2.csv')
OUT = Path('reports/cicapt_full_split_v2_preflight_fixed.json')
REQUIRED = ('ts', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol Type', 'label')


def canonical_key(src: str, sport: str, dst: str, dport: str, proto: str) -> str:
    src_ip = str(ipaddress.ip_address(src.strip()))
    dst_ip = str(ipaddress.ip_address(dst.strip()))
    src_port = int(sport)
    dst_port = int(dport)
    protocol = int(proto)
    if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535 and 0 <= protocol <= 255):
        raise ValueError(f'Invalid ports or protocol: {sport}, {dport}, {proto}')
    endpoints = sorted(((src_ip, src_port), (dst_ip, dst_port)))
    return json.dumps([protocol, endpoints], separators=(',', ':'))


def canonical_key_with_non_ip_fallback(src: str, sport: str, dst: str, dport: str, proto: str):
    """Return (grouping_key, non_ip_raw_values).

    Valid-IP flow key is IDENTICAL to scripts 18/19. For source-provided
    non-IP address placeholders such as '0', use an explicitly namespaced,
    deterministic 5-tuple-like key. This DOES NOT certify it is a true flow.
    """
    ports = (int(sport), int(dport))
    protocol = int(proto)
    if not (0 <= ports[0] <= 65535 and 0 <= ports[1] <= 65535 and 0 <= protocol <= 255):
        raise ValueError(f'Invalid ports or protocol: {sport!r}, {dport!r}, {proto!r}')
    non_ip = []
    endpoints = []
    for raw_ip, port in ((src, ports[0]), (dst, ports[1])):
        raw_ip = raw_ip.strip()
        try:
            normalized = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            non_ip.append(raw_ip)
            normalized = 'non-ip-token:' + raw_ip
        endpoints.append((normalized, port))
    endpoints.sort()
    key = json.dumps([protocol, endpoints], separators=(',', ':'))
    if non_ip:
        # Cannot collide with canonical JSON keys in the positive flow mapping.
        key = 'NON_IP_SURROGATE_V1|' + key
    return key, tuple(non_ip)


def bucket(key: str) -> str:
    digest = hashlib.blake2b((SEED + '|' + key).encode('utf-8'), digest_size=8).digest()
    fraction = int.from_bytes(digest, 'big') / 2 ** 64
    if fraction < TARGET['train']:
        return 'train'
    if fraction < TARGET['train'] + TARGET['validation']:
        return 'validation'
    return 'test'


def load_positive(path: Path):
    positive = {}
    expected = {}
    with path.open('r', newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        needed = {'canonical_flow_key', 'proposed_split', 'attack_records'}
        missing = needed - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f'Missing v2 mapping columns: {sorted(missing)}')
        for row in reader:
            key = row['canonical_flow_key']
            part = row['proposed_split']
            count = int(row['attack_records'])
            if key in positive or part not in PARTS or count < 1:
                raise ValueError(f'Invalid/duplicate v2 positive flow: {key}')
            try:
                decoded = json.loads(key)
                if len(decoded) != 2 or len(decoded[1]) != 2:
                    raise ValueError('Incorrect canonical key encoding')
                recomputed = canonical_key(
                    decoded[1][0][0], decoded[1][0][1],
                    decoded[1][1][0], decoded[1][1][1], decoded[0]
                )
            except (ValueError, TypeError, IndexError, KeyError) as exc:
                raise ValueError(f'Unparseable canonical key: {key}') from exc
            if key != recomputed:
                raise ValueError(f'Noncanonical key in v2 plan: {key}')
            positive[key] = part
            expected[key] = count
    if len(positive) != 46 or sum(expected.values()) != 1004:
        raise ValueError(f'Unexpected v2 positive mapping: {len(positive)} flows, {sum(expected.values())} attack records')
    return positive, expected


def audit(raw: Path, pos_path: Path, output: Path, progress: int = 1_000_000):
    if not raw.is_file():
        raise FileNotFoundError(raw)
    if not pos_path.is_file():
        raise FileNotFoundError(pos_path)
    if output.exists():
        raise FileExistsError(f'Output already exists; will not overwrite: {output}')

    positive, expected = load_positive(pos_path)
    counts = Counter()
    source_counts = Counter()  # positive_group / benign_only_group by split and label
    positive_seen = Counter()
    positive_group_benign = Counter()
    non_ip_rows = Counter()  # Split -> benign rows containing at least one non-IP field
    non_ip_tokens = Counter()  # Raw token -> occurrences among rows
    non_ip_surrogate_groups = Counter()  # Grouping-key -> row count
    daily = Counter()
    rows_scanned = 0
    # Cache repeated directed 5-tuples: never stores the raw dataset in memory.
    @lru_cache(maxsize=131072)
    def partition(src, sport, dst, dport, proto):
        key, non_ip = canonical_key_with_non_ip_fallback(src, sport, dst, dport, proto)
        if non_ip:
            # No legitimate attack key can be in the surrogate namespace.
            return bucket(key), None, non_ip, key
        if key in positive:
            return positive[key], key, (), None
        return bucket(key), None, (), None

    with raw.open('r', newline='', encoding='utf-8-sig') as handle:
        reader = csv.reader(handle)
        header = next(reader)
        if len(header) != len(set(header)):
            raise ValueError('Duplicate raw CSV column names')
        missing = [name for name in REQUIRED if name not in header]
        if missing:
            raise ValueError(f'Missing raw CSV columns: {missing}')
        i = {name: header.index(name) for name in REQUIRED}
        for rows_scanned, record in enumerate(reader, start=1):
            if len(record) != len(header):
                raise ValueError(f'Wrong column count at record {rows_scanned}: {len(record)} instead of {len(header)}')
            label = record[i['label']].strip()
            if label not in ('0', '1'):
                raise ValueError(f'Invalid label at record {rows_scanned}: {label!r}')
            try:
                part, positive_key, non_ip_values, surrogate_key = partition(
                    record[i['Source IP']].strip(), record[i['Source Port']].strip(),
                    record[i['Destination IP']].strip(), record[i['Destination Port']].strip(),
                    record[i['Protocol Type']].strip(),
                )
            except ValueError as exc:
                raise ValueError(f'Invalid communication fields at raw record {rows_scanned}: {exc}') from exc
            if non_ip_values:
                if label == '1':
                    raise ValueError(f'Attack row {rows_scanned} contains non-IP address tokens {non_ip_values!r}; STOP, investigate')
                non_ip_rows[part] += 1
                non_ip_tokens.update(non_ip_values)
                non_ip_surrogate_groups[surrogate_key] += 1
            if label == '1':
                if positive_key is None:
                    raise ValueError(f'Attack flow in raw CSV absent from positive v2 mapping, at record {rows_scanned}')
                positive_seen[positive_key] += 1
            if positive_key is not None and label == '0':
                positive_group_benign[positive_key] += 1
            counts[(part, label)] += 1
            source_counts[(part, label, 'positive_group' if positive_key is not None else 'benign_only_group')] += 1
            ts = float(record[i['ts']])
            if not math.isfinite(ts):
                raise ValueError(f'Nonfinite timestamp at record {rows_scanned}')
            utc_day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d')
            daily[(part, label, utc_day)] += 1
            if progress and rows_scanned % progress == 0:
                print(f'  scanned {rows_scanned:,} records', flush=True)
    if len(positive_seen) != len(positive):
        raise ValueError(f'Only saw {len(positive_seen)} of {len(positive)} positive flow keys')
    discrepancies = [
        (key, expected[key], positive_seen[key]) for key in positive
        if expected[key] != positive_seen[key]
    ]
    if discrepancies:
        raise ValueError(f'Positive flow counts disagree with v2 report (first 5): {discrepancies[:5]}')

    by_part = {
        part: {
            'normal': counts[(part, '0')],
            'attack': counts[(part, '1')],
            'total': counts[(part, '0')] + counts[(part, '1')],
            'attack_prevalence_percent': round(100 * counts[(part, '1')] / max(1, counts[(part, '0')] + counts[(part, '1')]), 6),
            'benign_rows_in_positive_containing_flows': source_counts[(part, '0', 'positive_group')],
            'benign_rows_in_benign_only_flows': source_counts[(part, '0', 'benign_only_group')],
            'benign_rows_with_non_ip_address_tokens': non_ip_rows[part],
        }
        for part in PARTS
    }
    if any(by_part[p]['normal'] == 0 or by_part[p]['attack'] == 0 for p in PARTS):
        raise ValueError('At least one partition lacks benign or attack observations; STOP, revise split policy')
    report = {
        'project': 'J26-CS-336',
        'status': 'PREFLIGHT / NO TRAIN-VALIDATION-TEST CSV MATERIALIZED / NOT APPROVED FOR MODEL TRAINING',
        'source': str(raw),
        'source_bytes': raw.stat().st_size,
        'positive_mapping': str(pos_path),
        'positive_mapping_sha256': hashlib.sha256(pos_path.read_bytes()).hexdigest(),
        'algorithm': 'v2 positive-flow override; canonical valid-IP flows hashed; non-IP benign rows hashed by distinct raw-token surrogate grouping',
        'canonical_key_definition': '[int_protocol, [[normalized_ip, int_port], [normalized_ip, int_port]]] sorted endpoints; compact JSON',
        'benign_only_hash_seed': SEED,
        'benign_only_hash_thresholds': {'train': '<0.70', 'validation': '0.70..0.85', 'test': '>=0.85'},
        'counts_by_split': by_part,
        'counts_by_day': {
            day: {part: {
                'normal': daily[(part, '0', day)], 'attack': daily[(part, '1', day)]
            } for part in PARTS}
            for day in sorted({d for (_, _, d) in daily})
        },
        'positive_flow_keys_verified': len(positive_seen),
        'positive_observations_verified': sum(positive_seen.values()),
        'benign_records_in_positive_containing_groups_total': sum(positive_group_benign.values()),
        'benign_records_with_non_ip_address_tokens_total': sum(non_ip_rows.values()),
        'non_ip_address_tokens_most_common': non_ip_tokens.most_common(15),
        'non_ip_surrogate_group_count': len(non_ip_surrogate_groups),
        'non_ip_surrogate_groups_largest': [
            {'benign_records': n, 'assigned_split': bucket(key)}
            for key, n in non_ip_surrogate_groups.most_common(10)
        ],
        'largest_positive_group_by_benign_rows': [
            {'benign_records': n, 'assigned_split': positive[key]}
            for key, n in positive_group_benign.most_common(5)
        ],
        'total_raw_records': rows_scanned,
        'caveats': [
            'Target shares 70/15/15 are hash probabilities for benign-only flow keys, not guaranteed row percentages.',
            'v2 positive-group assignments were selected using known labels/categories; this is not a campaign-independent holdout.',
            'Bidirectional 5-tuple key equality prevents same-key cross-partition rows, not all temporal/session leakage.',
            'Attacker IP/port and selected TCP-flag behavior can be shortcut features; ablation and same-pair evaluation required.',
            'Only counts and grouping fields were processed; features/labels were not changed and no test records exported.',
            'No claim made that CICAPT CSV rows are verified raw PCAP packets.',
            'Non-IP address tokens (e.g. 0) on benign records are opaque placeholders, not verified hosts; distinct surrogate groups reduce splitting of identical records but are not genuine flows.',
            'All records are counted in the preflight; exclusion or separate handling of non-IP traffic must be decided before training.',
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    print('\n=== CICAPT FULL-DATA FLOW-V2 PRE-FLIGHT ===')
    print(f'Records scanned: {rows_scanned:,}; positive flows verified: {len(positive_seen)}; attack labels: {sum(positive_seen.values()):,}')
    print('PARTITION     NORMAL       ATTACK        TOTAL      ATTACK RATE')
    for part in PARTS:
        p = by_part[part]
        print(f'{part:11s} {p["normal"]:>10,} {p["attack"]:>11,} {p["total"]:>12,} {p["attack_prevalence_percent"]:>11.6f}%')
    print('Benign observations assigned through positive-containing flow mapping:')
    for part in PARTS:
        print(f'  {part:11s} {by_part[part]["benign_rows_in_positive_containing_flows"]:,}')
    print(f'Non-IP-address benign records: {sum(non_ip_rows.values()):,} across {len(non_ip_surrogate_groups):,} provisional surrogate groups')
    print('Non-IP tokens (top):', non_ip_tokens.most_common(8))
    print('By proposed split:', {part: non_ip_rows[part] for part in PARTS})
    print('IMPORTANT: Surrogate groups are not proven network flows. Review before freezing partition.')
    print(f'Report: {output}')
    print('Raw CSV / positive v2 mapping unchanged; no split files, model fitting, or held-out evaluation.')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, default=RAW)
    parser.add_argument('--positive-map', type=Path, default=POS)
    parser.add_argument('--output', type=Path, default=OUT)
    parser.add_argument('--progress', type=int, default=1_000_000)
    args = parser.parse_args()
    try:
        audit(args.raw, args.positive_map, args.output, args.progress)
    except (OSError, ValueError, csv.Error, OverflowError) as exc:
        parser.exit(1, f'STOP: {exc}\n')


if __name__ == '__main__':
    main()
