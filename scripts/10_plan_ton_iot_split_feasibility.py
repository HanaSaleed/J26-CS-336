"""J26-CS-336 Phase 5 — read-only ToN-IoT train/test split feasibility check.

Usage: run with the project Python interpreter from the project root:
  python scripts/10_plan_ton_iot_split_feasibility.py

Why: review repeated feature patterns and whether an endpoint/flow-group holdout
would leave enough label and attack-type coverage for a meaningful test.

No train/test split is generated. No ML training. No original files are modified.
Only the Python standard library is required.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

FEATURES = (
    'src_port', 'dst_port', 'proto', 'service', 'duration',
    'src_bytes', 'dst_bytes', 'conn_state', 'src_pkts', 'dst_pkts',
)
NEEDED = (*FEATURES, 'src_ip', 'dst_ip', 'label', 'type')


def fingerprint(row: dict[str, str]) -> bytes:
    # The raw 10-feature representation, excluding IPs and label/type.
    raw_values = [row[k].strip() for k in FEATURES]
    data = json.dumps(raw_values, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return hashlib.blake2b(data, digest_size=16).digest()


def pair_key(row: dict[str, str]) -> tuple[str, str]:
    # Undirected IP pair (same group in both directions).
    return tuple(sorted((row['src_ip'].strip(), row['dst_ip'].strip())))


def conversation_key(row: dict[str, str]) -> tuple[str, tuple[str, str], tuple[str, str]]:
    # Bidirectional 5-tuple: IP, port, IP, port and protocol. This is a
    # grouping key, NOT proof of a unique connection/session identifier.
    a = (row['src_ip'].strip(), row['src_port'].strip())
    b = (row['dst_ip'].strip(), row['dst_port'].strip())
    return (row['proto'].strip().lower(), *sorted((a, b)))


def summarize_groups(title: str, groups: dict, by_type: dict, total: int) -> None:
    total_groups = len(groups)
    mixed = sum(1 for labels in groups.values() if len(labels) > 1)
    largest = max((sum(v.values()) for v in groups.values()), default=0)
    print(f'\n=== {title} ===')
    print('Distinct groups:', f'{total_groups:,}')
    print('Groups containing BOTH label values:', f'{mixed:,}')
    print('Largest group records:', f'{largest:,}', f'({largest / total * 100:.2f}% of file)' if total else '')
    print('Attack-type coverage: type -> groups containing it / records in largest group / total records')
    for typ, cnt in sorted(by_type.items()):
        largest_for_type = max(cnt.values(), default=0)
        all_for_type = sum(cnt.values())
        print(f'  {typ:14s}: groups={len(cnt):5,}, largest={largest_for_type:7,}/{all_for_type:7,}'
              f' ({largest_for_type / all_for_type * 100:.1f}%)' if all_for_type else f'  {typ}: none')
    print('NOTE: Many records per group, mixed-label groups, or a type present in very few')
    print('groups can make a held-out evaluation difficult. This is a feasibility check only.')


def scan(csv_path: Path) -> None:
    if not csv_path.is_file():
        raise FileNotFoundError(f'File not found: {csv_path}')
    print('=== J26-CS-336 TON-IOT SPLIT FEASIBILITY (READ ONLY) ===')
    print('Input:', csv_path.resolve())
    print('No output CSV is written. No model training or relabeling.')

    labels = Counter()
    types = Counter()
    pair_groups = defaultdict(Counter)
    convo_groups = defaultdict(Counter)
    pair_by_type = defaultdict(Counter)
    convo_by_type = defaultdict(Counter)
    feature_sig_labels = defaultdict(Counter)
    total = invalid = 0

    with csv_path.open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        missing = sorted(set(NEEDED) - set(reader.fieldnames or ()))
        if missing:
            raise ValueError('Missing required columns: ' + ', '.join(missing))
        for row in reader:
            total += 1
            if None in row or any(row.get(c) is None for c in NEEDED):
                invalid += 1
                continue
            lab = row['label'].strip()
            typ = row['type'].strip()
            labels[lab] += 1
            types[typ] += 1
            pair = pair_key(row)
            convo = conversation_key(row)
            pair_groups[pair][lab] += 1
            convo_groups[convo][lab] += 1
            pair_by_type[typ][pair] += 1
            convo_by_type[typ][convo] += 1
            feature_sig_labels[fingerprint(row)][lab] += 1

    print('\n=== RECORD SUMMARY ===')
    print('Rows:', f'{total:,}', '| bad width / incomplete:', f'{invalid:,}')
    print('Labels:', dict(sorted(labels.items())))
    print('Types:', dict(sorted(types.items())))
    print('Candidate features (label/type and raw IPs excluded):', ', '.join(FEATURES))
    groups_with_duplicates = sum(1 for labs in feature_sig_labels.values() if sum(labs.values()) > 1)
    extra_repeated_rows = sum(sum(labs.values()) - 1 for labs in feature_sig_labels.values())
    mixed_signature_groups = sum(1 for labs in feature_sig_labels.values() if len(labs) > 1)
    mixed_signature_rows = sum(sum(labs.values()) for labs in feature_sig_labels.values() if len(labs) > 1)
    print('\n=== SAME 10-FEATURE SIGNATURES ===')
    print('Distinct signatures:', f'{len(feature_sig_labels):,}')
    print('Groups containing duplicates:', f'{groups_with_duplicates:,}')
    print('Additional rows repeating a previous 10-feature signature:', f'{extra_repeated_rows:,}')
    print('Signature groups with BOTH label values:', f'{mixed_signature_groups:,}')
    print('Rows in mixed-label signature groups:', f'{mixed_signature_rows:,}')
    print('Identical features do NOT automatically imply identical real-world events.')

    summarize_groups('BIDIRECTIONAL IP-PAIR GROUPS', pair_groups, pair_by_type, total)
    summarize_groups('BIDIRECTIONAL 5-TUPLE GROUPS', convo_groups, convo_by_type, total)

    print('\n=== INTERPRETATION / NEXT GATE ===')
    print('This dataset lacks event timestamps and source session/campaign identifiers.')
    print('The file name train_test_network.csv does not itself prove a valid experimental split.')
    print('Do NOT randomly split, deduplicate, export data or train a model yet.')
    print('Share this output to choose a feasible group-disjoint evaluation and')
    print('a categorical encoding plan. We will keep 5/10/15/20s tests separate.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', type=Path, default=Path('data/raw/ton_iot_train_test_network.csv'))
    args = parser.parse_args()
    scan(args.csv)


if __name__ == '__main__':
    main()
