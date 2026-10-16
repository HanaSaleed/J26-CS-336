"""J26-CS-336 Phase 5: READ-ONLY ToN-IoT network-flow training-readiness audit.

Usage:
    python scripts/09_audit_ton_iot_flow_readiness.py
    python scripts/09_audit_ton_iot_flow_readiness.py --csv path/to/file.csv

Does NOT train, label, modify, or export datasets. No third-party packages.
The supplied ToN-IoT CSV is connection-level; it has no timestamp column.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

REQUIRED = (
    'src_ip','src_port','dst_ip','dst_port','proto','service','duration',
    'src_bytes','dst_bytes','conn_state','src_pkts','dst_pkts','label','type',
)
NUMERIC = ('src_port','dst_port','duration','src_bytes','dst_bytes','src_pkts','dst_pkts')
CANDIDATE_FEATURES = (
    'src_port','dst_port','proto','service','duration','src_bytes',
    'dst_bytes','conn_state','src_pkts','dst_pkts',
)
NULL_MARKERS = ('', '-', 'nan', 'null', 'none', 'na')


def sig(values):
    payload = json.dumps(values, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return hashlib.blake2b(payload, digest_size=16).digest()


def scan(csv_path: Path) -> None:
    if not csv_path.is_file():
        raise FileNotFoundError(f'CSV not found: {csv_path}')
    print('=== J26-CS-336 TON-IOT FLOW READINESS (READ ONLY) ===')
    print(f'Input: {csv_path.resolve()}')
    print('No data will be modified, copied or used for model training.')
    with csv_path.open('r', encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            raise ValueError('Missing CSV header')
        headers = reader.fieldnames
        missing_required = [f for f in REQUIRED if f not in headers]
        print(f'Columns: {len(headers)}; required present: {len(REQUIRED)-len(missing_required)}/{len(REQUIRED)}')
        if missing_required:
            raise ValueError('Missing required columns: ' + ', '.join(missing_required))
        print('Timestamp columns (ts, timestamp, start_time, time): ' +
              (', '.join(f for f in headers if f.lower() in ('ts','timestamp','start_time','time')) or 'NONE'))
        features_without_labels = [f for f in headers if f not in ('label','type')]
        labels, types, combo = Counter(), Counter(), Counter()
        proto, service, conn_state = Counter(), Counter(), Counter()
        missing = Counter()
        numeric_bad = Counter()
        ips_src, ips_dst = set(), set()
        full_seen = {}  # 16-byte fingerprints for all nonlabel columns
        full_dupe = full_conflict = 0
        core_seen = {}
        core_dupe = core_conflict = 0
        rows = invalid_width = 0
        examples = []
        for row in reader:
            rows += 1
            if None in row or any(row.get(h) is None for h in headers):
                invalid_width += 1
                continue
            lab = row['label'].strip()
            typ = row['type'].strip()
            labels[lab] += 1
            types[typ] += 1
            combo[(lab, typ)] += 1
            proto[row['proto'].strip()] += 1
            service[row['service'].strip()] += 1
            conn_state[row['conn_state'].strip()] += 1
            ips_src.add(row['src_ip'].strip())
            ips_dst.add(row['dst_ip'].strip())
            for f in CANDIDATE_FEATURES:
                if row[f].strip().lower() in NULL_MARKERS:
                    missing[f] += 1
            for f in NUMERIC:
                v = row[f].strip()
                if v.lower() in NULL_MARKERS:
                    continue
                try:
                    if not math.isfinite(float(v)):
                        numeric_bad[f] += 1
                except ValueError:
                    numeric_bad[f] += 1
            key = sig([row[f] for f in features_without_labels])
            if key in full_seen:
                full_dupe += 1
                if full_seen[key] != lab:
                    full_conflict += 1
                    if len(examples) < 2:
                        examples.append((rows, lab, full_seen[key]))
            else:
                full_seen[key] = lab
            core_key = sig([row[f] for f in CANDIDATE_FEATURES])
            if core_key in core_seen:
                core_dupe += 1
                if core_seen[core_key] != lab:
                    core_conflict += 1
            else:
                core_seen[core_key] = lab
    print(f'\n=== FILE CHECK ===\nRows read: {rows:,}; malformed width: {invalid_width:,}')
    print('Label counts:', dict(sorted(labels.items())))
    print('Type counts:', dict(sorted(types.items())))
    print('Label/type combinations:', {f'{a}/{b}':v for (a,b),v in sorted(combo.items())})
    print(f'Distinct source IPs: {len(ips_src):,}; destination IPs: {len(ips_dst):,}')
    print('Top protocols:', proto.most_common(8))
    print('Top services:', service.most_common(8))
    print('Top connection states:', conn_state.most_common(8))
    print('\n=== CANDIDATE FEATURE QUALITY ===')
    print('Candidate input columns:', ', '.join(CANDIDATE_FEATURES))
    print('Missing/placeholder markers in candidates:', {k:missing[k] for k in CANDIDATE_FEATURES if missing[k]})
    print('Non-numeric/non-finite values in numeric candidates:', {k:numeric_bad[k] for k in NUMERIC if numeric_bad[k]})
    print('\n=== REPEATED SIGNATURE SCREEN ===')
    print(f'All nonlabel columns: repeated signatures={full_dupe:,}; conflicting-label occurrences={full_conflict:,}')
    print(f'10 candidate inputs only: repeated signatures={core_dupe:,}; conflicting-label occurrences={core_conflict:,}')
    if examples:
        print('First conflicting full-input examples (row, observed_label, earlier_label):', examples)
    print('NOTE: A repeated signature is NOT proof of data leakage by itself. It shows a risk')
    print('if repeated or related records are randomly distributed across training and testing.')
    print('Conflicts on a reduced feature set may be expected because the inputs omit context.')
    print('\n=== RESEARCH DECISION ===')
    print('ToN-IoT can be investigated for CONNECTION/FLOW-LEVEL classification.')
    print('The supplied CSV has no event timestamp for reliable 5/10/15/20-second windows.')
    print('Do NOT mix ToN rows with CICAPT packet-like rows or train a window model on this CSV.')
    print('NEXT: agree on held-out test design, encoding, and duplicate-group handling.')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv', type=Path, default=Path('data/raw/ton_iot_train_test_network.csv'))
    args = p.parse_args()
    scan(args.csv)


if __name__ == '__main__':
    main()
