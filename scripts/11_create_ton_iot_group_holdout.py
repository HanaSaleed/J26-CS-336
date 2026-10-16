"""J26-CS-336 Phase 5 — reproducible, bidirectional 5-tuple group-disjoint ToN-IoT split.

Usage from D:\\IIoT-APT-Research:
  .\\.venv\\Scripts\\python.exe .\\scripts\\11_create_ton_iot_group_holdout.py

Creates NEW files under data/processed/ton_iot_group_holdout_v1/ only.
Never edits the original CSV; never trains a model. Standard library only.

IMPORTANT: 5-tuple disjoint DOES NOT guarantee signature-, IP-, session-, or
campaign-disjoint testing. The script reports feature-signature overlap.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

FEATURES = (
    'src_port', 'dst_port', 'proto', 'service', 'duration',
    'src_bytes', 'dst_bytes', 'conn_state', 'src_pkts', 'dst_pkts',
)
METADATA = ('label', 'type')
NEEDED = (*FEATURES, *METADATA, 'src_ip', 'dst_ip')
PARTITIONS = ('train', 'validation', 'test')
RATIOS = (0.70, 0.15, 0.15)
DEFAULT_SEED = 'J26-CS-336-ton-iot-groupholdout-v1-42'


def group_key(row: dict[str, str]) -> tuple:
    """Canonical bidirectional IP+port/IP+port+protocol; not a session ID."""
    a = (row['src_ip'].strip(), row['src_port'].strip())
    b = (row['dst_ip'].strip(), row['dst_port'].strip())
    return (row['proto'].strip().lower(), *sorted((a, b)))


def payload_hash(values: object, size: int = 16) -> str:
    raw = json.dumps(values, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return hashlib.blake2b(raw, digest_size=size).hexdigest()


def partition_for_group(key: tuple, seed: str) -> str:
    h = hashlib.blake2b((seed + '\0' + json.dumps(key, separators=(',', ':'))).encode('utf-8'), digest_size=8).digest()
    fraction = int.from_bytes(h, 'big') / 2**64
    return 'train' if fraction < RATIOS[0] else ('validation' if fraction < RATIOS[0] + RATIOS[1] else 'test')


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def split(path: Path, out: Path, seed: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f'Input CSV not found: {path}')
    if out.exists():
        raise FileExistsError(f'Output path already exists: {out}\nChoose a NEW versioned --output. Original files are untouched.')

    rows: list[tuple[str, list[str], str, str, str, str]] = []
    group_assignments: dict[tuple, str] = {}
    group_counts: Counter = Counter()
    labels: dict[str, Counter] = {p: Counter() for p in PARTITIONS}
    types: dict[str, Counter] = {p: Counter() for p in PARTITIONS}
    signatures: dict[str, set] = {p: set() for p in PARTITIONS}
    sign_counts: dict[str, Counter] = {p: Counter() for p in PARTITIONS}
    bad = 0
    original_labels: Counter = Counter()

    with path.open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        missing = sorted(set(NEEDED) - set(reader.fieldnames or []))
        if missing:
            raise ValueError('Required fields missing: ' + ', '.join(missing))
        for rownum, row in enumerate(reader, start=2):
            if None in row or any(row.get(k) is None for k in NEEDED):
                bad += 1
                continue
            label = row['label'].strip()
            typ = row['type'].strip()
            if label not in {'0', '1'}:
                raise ValueError(f'Unexpected label at physical CSV line {rownum}: {label!r}')
            original_labels[label] += 1
            key = group_key(row)
            part = group_assignments.get(key)
            if part is None:
                part = partition_for_group(key, seed)
                group_assignments[key] = part
            vals = [row[c].strip() for c in FEATURES]
            sig = payload_hash(vals)
            rows.append((part, vals, label, typ, sig, payload_hash(key)))
            labels[part][label] += 1
            types[part][typ] += 1
            group_counts[part] += (0 if group_counts.get((part, key)) else 1)
            group_counts[(part, key)] = 1
            signatures[part].add(sig)
            sign_counts[part][sig] += 1

    n = len(rows)
    if bad:
        raise ValueError(f'Found {bad} malformed records: stop and review (no outputs written).')
    if not n:
        raise ValueError('Dataset is empty.')
    all_types = set().union(*(set(c) for c in types.values()))
    print('=== J26-CS-336 TON-IOT GROUP-DISJOINT SPLIT ===')
    print('Input:', path.resolve())
    print('Rows:', f'{n:,}', 'groups:', f'{len(group_assignments):,}')
    print('Group definition: canonical bidirectional (src IP,port) + (dst IP,port) + protocol')
    print('Assignment: fixed-seed stable hash, requested ratios 70% / 15% / 15%')
    print('No model training; original CSV is never changed.')
    print('\n=== PROPOSED PARTITIONS ===')
    for part in PARTITIONS:
        cnt = sum(labels[part].values())
        print(f'{part:10s} records={cnt:7,} ({cnt/n:.2%}) groups={group_counts[part]:7,} labels={dict(labels[part])}')
        print('  attack types:', dict(sorted(types[part].items())))

    # Abort before writing on major representation problems. This protects a
    # fixed-seed design instead of quietly cherry-picking an evaluation split.
    for part, expected in zip(PARTITIONS, RATIOS):
        fraction = sum(labels[part].values()) / n
        if abs(fraction - expected) > 0.09:
            raise ValueError(f'{part} proportion {fraction:.1%} is too far from requested {expected:.0%}; inspect before exporting.')
        if not {'0', '1'}.issubset(labels[part]):
            raise ValueError(f'Both binary labels are not present in {part}; inspect before exporting.')
        absent = all_types - set(types[part])
        if absent:
            raise ValueError(f'{part} lacks attack types {sorted(absent)}; inspect before exporting.')

    print('\n=== IDENTICAL 10-INPUT SIGNATURE OVERLAP ===')
    overlap_report = {}
    for part in ('validation', 'test'):
        overlap = signatures[part] & signatures['train']
        n_rows_in_overlap = sum(sign_counts[part][sig] for sig in overlap)
        total_part = sum(labels[part].values())
        print(f'{part:10s}: {len(overlap):,} signatures also occur in TRAIN; '
              f'{n_rows_in_overlap:,}/{total_part:,} rows ({n_rows_in_overlap/total_part:.2%})')
        overlap_report[part] = {
            'overlapping_distinct_signatures': len(overlap),
            'rows_with_signature_seen_in_train': n_rows_in_overlap,
            'fraction_rows': round(n_rows_in_overlap / total_part, 6),
        }
    print('CAUTION: Group-disjoint DOES NOT ensure unseen input signatures or new sessions/campaigns.')
    print('A repeated signature is a generalization concern, not automatic proof of improper leakage.')

    # Prepare data before writing. Never overwrite a versioned output folder.
    out.mkdir(parents=True, exist_ok=False)
    writers: dict[str, csv.writer] = {}
    handles = {}
    try:
        for part in PARTITIONS:
            fh = (out / f'{part}.csv').open('w', newline='', encoding='utf-8')
            handles[part] = fh
            writer = csv.writer(fh)
            writer.writerow([*FEATURES, *METADATA])
            writers[part] = writer
        for part, vals, label, typ, sig, group_digest in rows:
            writers[part].writerow([*vals, label, typ])
    finally:
        for fh in handles.values():
            fh.close()

    manifest = {
        'project': 'J26-CS-336', 'version': 'ton_iot_group_holdout_v1',
        'generated_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'source_file': str(path.resolve()), 'source_size_bytes': path.stat().st_size,
        'source_sha256': file_sha256(path),
        'assignment_seed': seed,
        'assignment': 'stable hash of bidirectional 5-tuple; 70/15/15 hash ranges, not label-stratified',
        'group_warning': '5-tuple is not a verified session/campaign identifier; IP-pair overlap may remain.',
        'candidate_input_features': list(FEATURES),
        'excluded_input_fields': ['src_ip', 'dst_ip', 'label', 'type'],
        'metadata_output_columns': list(METADATA),
        'preprocessing_not_yet_done': True,
        'preprocessing_plan': {
            'numeric': ['src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes', 'src_pkts', 'dst_pkts'],
            'categorical': ['proto', 'service', 'conn_state'],
            'unknown_service': "Keep '-' as an explicit observed category; do not invent a protocol service.",
            'training_only_fit': 'Fit any imputer/encoder exclusively on train.csv, then transform validation and test.',
        },
        'rows_total': n, 'groups_total': len(group_assignments),
        'partitions': {
            p: {'rows': sum(labels[p].values()), 'groups': group_counts[p],
                'label_counts': dict(labels[p]), 'type_counts': dict(types[p])}
            for p in PARTITIONS
        },
        'exact_signature_overlap_with_train': overlap_report,
        'not_a_window_dataset': 'No event timestamps; no 5/10/15/20-second training claims.',
        'not_leakage_free': 'Exact feature signatures can occur in multiple groups and partitions.',
    }
    (out / 'split_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('\n=== FILES CREATED ===')
    for fn in ('train.csv', 'validation.csv', 'test.csv', 'split_manifest.json'):
        print(' ', out / fn)
    print('COMPLETED: 5-tuple-group-disjoint split. No encoder fit, no ML training.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', type=Path, default=Path('data/raw/ton_iot_train_test_network.csv'))
    parser.add_argument('--output', type=Path, default=Path('data/processed/ton_iot_group_holdout_v1'))
    parser.add_argument('--seed', default=DEFAULT_SEED)
    args = parser.parse_args()
    split(args.csv, args.output, args.seed)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        print('STOPPED:', exc, file=sys.stderr)
        sys.exit(1)
