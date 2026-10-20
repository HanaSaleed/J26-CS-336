#!/usr/bin/env python3
"""J26-CS-336 | Checkpoint 04.1: materialize ONLY CICAPT training and validation.

Run from D:\\IIoT-APT-Research:
  .\\.venv\\Scripts\\python.exe .\\scripts\\22_materialize_cicapt_train_validation_v2.py

- Verify frozen manifest hashes, expected class counts and Phase-2 byte size.
- Recompute the exact flow-v2 grouping and benign-only flow hash partition.
- Drop only the 74,995 verified benign, zero-address ARP records from this
  IP-addressed packet-level baseline. Keep the original dataset unchanged.
- Output ALL positive train rows; select deterministic training negatives only.
- Output ALL validation rows at natural prevalence.
- Route test rows but NEVER output their features or labels, train on them,
  or examine test model outcomes.
- Do not treat source CSV rows as proven original PCAP packets.
- Do not include raw IP, epoch timestamp, sub-label, flow key or row number
  in exported ML data.  The label column is the separate TARGET only.
- Outputs are created ONLY after full-file consistency checks succeed.
  Existing output files are never overwritten.

Dependencies: Python 3.10+ standard library. No pandas required.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
from collections import Counter
from functools import lru_cache
from pathlib import Path

RAW = Path('data/raw/cicapt_IIOT_phase2_NetworkData.csv')
PLAN = Path('reports/cicapt_flow_split_plan_v2.json')
POS = Path('reports/cicapt_positive_flow_split_v2.csv')
PREFLIGHT = Path('reports/cicapt_full_split_v2_preflight_fixed.json')
MANIFEST = Path('reports/cicapt_ip_packet_baseline_v2_manifest.json')
OUT_DIR = Path('data/processed/cicapt_packet_baseline_v2')
TRAIN = OUT_DIR / 'train_sampled.csv'
VALID = OUT_DIR / 'validation_natural.csv'
SUMMARY = OUT_DIR / 'materialization_summary.json'

PARTS = ('train', 'validation', 'test')
SPLIT_SEED = 'J26-CS-336|CICAPT|flow-v1'
SAMPLE_SEED = 'J26-CS-336|CICAPT|train-normal-sampling-v1'
REQUIRED = (
    'Source IP', 'Destination IP', 'Source Port', 'Destination Port',
    'Protocol Type', 'Tot size', 'syn_flag_number', 'ack_flag_number',
    'rst_flag_number', 'fin_flag_number', 'psh_flag_number',
    'label', 'ARP', 'IPv',
)
FIELDS = (
    'proto', 'frame_size', 'syn_flag', 'ack_flag', 'rst_flag',
    'fin_flag', 'psh_flag', 'src_port', 'dst_port', 'label',
)
FLAG_NAMES = ('syn_flag_number', 'ack_flag_number', 'rst_flag_number',
              'fin_flag_number', 'psh_flag_number')


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_key(src: str, sport: str, dst: str, dport: str, proto: str) -> str:
    # EXACT encoding used by scripts 18, 20, and the frozen split manifest.
    a = str(ipaddress.ip_address(src.strip()))
    b = str(ipaddress.ip_address(dst.strip()))
    pa, pb, p = int(sport), int(dport), int(proto)
    if not (0 <= pa <= 65535 and 0 <= pb <= 65535 and 0 <= p <= 255):
        raise ValueError('Invalid port or IP protocol')
    return json.dumps([p, sorted(((a, pa), (b, pb)))], separators=(',', ':'))


def benign_partition(key: str) -> str:
    value = hashlib.blake2b(
        (SPLIT_SEED + '|' + key).encode('utf-8'), digest_size=8
    ).digest()
    fraction = int.from_bytes(value, 'big') / (2 ** 64)
    return 'train' if fraction < .70 else ('validation' if fraction < .85 else 'test')


def include_training_normal(row_index: int, probability: float) -> bool:
    # Uniform deterministic row sampling, train partition ONLY.  Do not call
    # this on validation or test observations.
    value = hashlib.blake2b(
        (SAMPLE_SEED + '|' + str(row_index)).encode('utf-8'), digest_size=8
    ).digest()
    return int.from_bytes(value, 'big') / (2 ** 64) < probability


def check_sources():
    for path in (RAW, PLAN, POS, PREFLIGHT, MANIFEST):
        if not path.is_file():
            raise ValueError(f'Missing required source: {path}')
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8-sig'))
    expected_hashes = manifest.get('source_artifacts_sha256', {})
    for file in (PLAN, POS, PREFLIGHT):
        expected = expected_hashes.get(str(file))
        if not expected or sha256(file) != expected:
            raise ValueError(f'Frozen manifest hash mismatch: {file}')
    if RAW.stat().st_size != int(manifest['raw_source']['bytes']):
        raise ValueError('Raw CSV file size changed since manifest freeze')
    if manifest['eligibility_policy']['excluded_record_count'] != 74995:
        raise ValueError('Manifest ARP exclusion policy unexpected')
    if manifest['totals']['eligible_ip_addressed_candidate_records'] != 9461828:
        raise ValueError('Manifest eligible total unexpected')
    by_split = manifest['counts_by_split_after_arp_exclusion']
    if [(int(by_split[p]['attack_labeled_records'])) for p in PARTS] != [712, 146, 146]:
        raise ValueError('Unexpected frozen positive counts')
    positive = {}
    positive_expected = {}
    with POS.open('r', encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        needed = {'canonical_flow_key', 'proposed_split', 'attack_records'}
        if not needed.issubset(reader.fieldnames or ()):
            raise ValueError('Positive flow mapping columns unexpected')
        for record in reader:
            key, part = record['canonical_flow_key'], record['proposed_split']
            if key in positive or part not in PARTS:
                raise ValueError('Duplicate or invalid positive mapping')
            positive[key] = part
            positive_expected[key] = int(record['attack_records'])
    if len(positive) != 46:
        raise ValueError('Expected exactly 46 positive-flow groups')
    return manifest, positive, positive_expected


def extracted_fields(row: list[str], i: dict[str, int]) -> list[str]:
    """Make ONLY packet-like candidate features + separate label column.

    Ports are retained for controlled ablations; exclude them from the first
    recommended strict behavioral baseline. No preprocessing/scaling is fitted
    here.  The training script must use an explicit feature allowlist.
    """
    proto = int(row[i['Protocol Type']].strip())
    src_port = int(row[i['Source Port']].strip())
    dst_port = int(row[i['Destination Port']].strip())
    size = float(row[i['Tot size']].strip())
    if not (0 < size <= 1_000_000 and math.isfinite(size)):
        raise ValueError(f'Invalid Tot size: {size}')
    flags = []
    for flag in FLAG_NAMES:
        value = float(row[i[flag]].strip())
        if value not in (0.0, 1.0):
            raise ValueError(f'Nonbinary current TCP flag {flag}={value!r}')
        flags.append(str(int(value)))
    return [str(proto), format(size, '.15g'), *flags,
            str(src_port), str(dst_port), row[i['label']].strip()]


def is_excluded_arp(row: list[str], i: dict[str, int]) -> bool:
    src, dst = row[i['Source IP']].strip(), row[i['Destination IP']].strip()
    if src != '0' and dst != '0':
        return False
    if not (src == dst == '0' and
            row[i['Source Port']].strip() == '0' and
            row[i['Destination Port']].strip() == '0' and
            row[i['Protocol Type']].strip() == '0' and
            row[i['ARP']].strip() == '1' and
            row[i['IPv']].strip() == '0' and
            row[i['label']].strip() == '0'):
        raise ValueError('Encountered unexpected zero-address record; do not silently skip')
    return True


def run(normal_ratio: int, progress: int = 1_000_000):
    manifest, positive, positive_expected = check_sources()
    if not 1 <= normal_ratio <= 1000:
        raise ValueError('--train-normal-per-attack must be from 1 to 1000')
    expected = manifest['counts_by_split_after_arp_exclusion']
    train_normal = int(expected['train']['eligible_normal_records'])
    train_attacks = int(expected['train']['attack_labeled_records'])
    target_normal = train_attacks * normal_ratio
    probability = min(1.0, target_normal / train_normal)
    if any(p.exists() for p in (TRAIN, VALID, SUMMARY)):
        raise ValueError(f'An output already exists in {OUT_DIR}. Do not overwrite')
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    partial_train = OUT_DIR / 'train_sampled.csv.partial'
    partial_valid = OUT_DIR / 'validation_natural.csv.partial'
    if partial_train.exists() or partial_valid.exists():
        raise ValueError('Prior .partial output exists; inspect before retrying')

    counts = Counter()  # Counts ALL routed eligible records, including held-out.
    saved = Counter()
    positive_seen = Counter()
    ip_versions = Counter()
    arp_count = 0
    rows_seen = 0

    @lru_cache(maxsize=131072)
    def partition(src: str, sport: str, dst: str, dport: str, proto: str):
        key = canonical_key(src, sport, dst, dport, proto)
        return positive.get(key, benign_partition(key)), key, (
            ipaddress.ip_address(src).version, ipaddress.ip_address(dst).version
        )

    try:
        with (RAW.open('r', encoding='utf-8-sig', newline='') as source,
              partial_train.open('x', encoding='utf-8', newline='') as train_f,
              partial_valid.open('x', encoding='utf-8', newline='') as valid_f):
            reader = csv.reader(source)
            header = next(reader)
            if len(header) != len(set(header)) or len(header) != 70:
                raise ValueError('Expected exactly 70 distinct raw columns')
            missing = set(REQUIRED).difference(header)
            if missing:
                raise ValueError(f'Missing CSV columns: {sorted(missing)}')
            i = {name: header.index(name) for name in REQUIRED}
            writer_train, writer_valid = csv.writer(train_f), csv.writer(valid_f)
            writer_train.writerow(FIELDS)
            writer_valid.writerow(FIELDS)
            for rows_seen, row in enumerate(reader, 1):
                if progress and rows_seen % progress == 0:
                    print(f'  scanned {rows_seen:,} source rows', flush=True)
                if len(row) != len(header):
                    raise ValueError(f'Wrong CSV width at record {rows_seen}')
                label = row[i['label']].strip()
                if label not in ('0', '1'):
                    raise ValueError(f'Invalid label at row {rows_seen}: {label}')
                if is_excluded_arp(row, i):
                    arp_count += 1
                    continue
                src = row[i['Source IP']].strip()
                sport = row[i['Source Port']].strip()
                dst = row[i['Destination IP']].strip()
                dport = row[i['Destination Port']].strip()
                proto = row[i['Protocol Type']].strip()
                try:
                    part, key, versions = partition(src, sport, dst, dport, proto)
                except ValueError as exc:
                    raise ValueError(f'Bad IP/port/protocol at record {rows_seen}: {exc}') from exc
                ip_versions[versions] += 1
                counts[(part, label)] += 1
                if label == '1':
                    if key not in positive:
                        raise ValueError(f'Unexpected positive flow at row {rows_seen}')
                    positive_seen[key] += 1
                # HOLDOUT: NEVER construct, save, inspect or use test features.
                if part == 'test':
                    continue
                if part == 'train' and label == '0':
                    if not include_training_normal(rows_seen, probability):
                        continue
                try:
                    feature_row = extracted_fields(row, i)
                except ValueError as exc:
                    raise ValueError(f'Bad feature at record {rows_seen}: {exc}') from exc
                if part == 'train':
                    writer_train.writerow(feature_row)
                else:
                    writer_valid.writerow(feature_row)
                saved[(part, label)] += 1
        if rows_seen != int(manifest['raw_source']['total_records']):
            raise ValueError(f'Raw rows {rows_seen} do not match frozen manifest')
        if arp_count != 74995:
            raise ValueError(f'ARP exclusions changed: {arp_count} != 74995')
        for part in PARTS:
            for label, col in (('0', 'eligible_normal_records'), ('1', 'attack_labeled_records')):
                need = int(expected[part][col])
                if counts[(part, label)] != need:
                    raise ValueError(f'Partition {part}/label={label}: saw {counts[(part,label)]}, expected {need}. STOP')
        if len(positive_seen) != 46 or sum(positive_seen.values()) != 1004:
            raise ValueError('Positive mapping consistency failed')
        if any(positive_seen[k] != positive_expected[k] for k in positive):
            raise ValueError('Individual positive-flow counts differ from frozen mapping')
        if saved[('train','1')] != train_attacks or saved[('validation','1')] != int(expected['validation']['attack_labeled_records']):
            raise ValueError('Missing exported attack records')
        if saved[('validation','0')] != int(expected['validation']['eligible_normal_records']):
            raise ValueError('Validation benign distribution changed')
        if saved[('test','0')] or saved[('test','1')]:
            raise ValueError('Test observations were accidentally exported')
        summary = {
            'project': 'J26-CS-336',
            'status': 'train and natural validation materialized; TEST UNEXPORTED',
            'raw': str(RAW),
            'frozen_manifest': str(MANIFEST),
            'frozen_manifest_sha256': sha256(MANIFEST),
            'training_benign_sample': {
                'method': 'deterministic uniform row selection from TRAIN ONLY, BLAKE2b 8-byte digest',
                'seed': SAMPLE_SEED, 'normal_per_attack_target': normal_ratio,
                'inclusion_probability': probability,
                'expected_normal_sample_size': target_normal,
                'actual_normal_sample_size': saved[('train','0')],
                'no_resampling_of_validation_or_test': True,
            },
            'feature_allowlist_first_baseline': [
                'proto', 'frame_size', 'syn_flag', 'ack_flag', 'rst_flag', 'fin_flag', 'psh_flag'
            ],
            'stored_but_not_first_baseline': ['src_port', 'dst_port'],
            'label_column_target_only': 'label',
            'observations_routed_by_split': {
                p: {'normal':counts[(p,'0')], 'attack':counts[(p,'1')]} for p in PARTS
            },
            'observations_exported': {
                'train': {'normal':saved[('train','0')], 'attack':saved[('train','1')]},
                'validation': {'normal':saved[('validation','0')], 'attack':saved[('validation','1')]},
                'test': 'NO FILE GENERATED',
            },
            'address_versions_all_eligible': {
                f'{src}->{dst}': n for (src,dst), n in sorted(ip_versions.items())
            },
            'excluded_source_rows_benign_arp': arp_count,
            'warning': 'The train benign subset changes prevalence; predicted probabilities are NOT calibrated. Model evaluation must use untouched natural validation, with test reserved.',
        }
        # Create final data only after all consistency checks pass.
        with SUMMARY.open('x', encoding='utf-8') as report:
            json.dump(summary, report, indent=2)
            report.write('\n')
        os.replace(partial_train, TRAIN)
        os.replace(partial_valid, VALID)
    except Exception:
        for temp in (partial_train, partial_valid):
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    print('=== CICAPT CHECKPOINT 04.1 TRAIN/VALID MATERIALIZATION ===')
    print(f'Frozen grouping + manifest verification: PASS')
    print(f'Raw source records routed: {rows_seen:,}; benign ARP excluded: {arp_count:,}')
    print(f'Train: {saved[("train","0")]:,} sampled normal + {saved[("train","1")]:,} attack')
    print(f'Validation: {saved[("validation","0")]:,} natural normal + {saved[("validation","1")]:,} attack')
    print('Test: no rows exported; held-out portion reserved')
    print('Eligible IP version pairs:', {f'{a}->{b}': n for (a,b), n in sorted(ip_versions.items())})
    print(f'Sampled train: {TRAIN}')
    print(f'Natural validation: {VALID}')
    print(f'Manifest: {SUMMARY}')
    print('No model training or held-out test assessment performed.')


def self_test():
    k1 = canonical_key('172.16.63.128', '41596', '172.16.65.128', '8888', '6')
    k2 = canonical_key('172.16.65.128', '8888', '172.16.63.128', '41596', '6')
    assert k1 == k2
    assert k1 == '[6,[["172.16.63.128",41596],["172.16.65.128",8888]]]'
    assert benign_partition(k1) in PARTS
    assert include_training_normal(123, 1.0)
    assert not include_training_normal(123, 0.0)
    fields = {k:j for j, k in enumerate(REQUIRED)}
    record = ['0']*len(REQUIRED)
    record[fields['Source IP']] = '0'
    record[fields['Destination IP']] = '0'
    record[fields['Source Port']] = '0'
    record[fields['Destination Port']] = '0'
    record[fields['Protocol Type']] = '0'
    record[fields['ARP']] = '1'
    record[fields['IPv']] = '0'
    record[fields['label']] = '0'
    assert is_excluded_arp(record, fields)
    record[fields['ARP']] = '0'
    try:
        is_excluded_arp(record, fields)
        raise AssertionError('Invalid non-IP should stop')
    except ValueError:
        pass
    record[fields['Source IP']] = '192.0.2.1'
    record[fields['Destination IP']] = '192.0.2.2'
    record[fields['Source Port']] = '1234'
    record[fields['Destination Port']] = '8888'
    record[fields['Protocol Type']] = '6'
    record[fields['Tot size']] = '66'
    record[fields['ack_flag_number']] = '1'
    value = extracted_fields(record, fields)
    assert value == ['6', '66', '0', '1', '0', '0', '0', '1234', '8888', '0'], value
    print('SELF-TEST PASS: canonical grouping, sampling, ARP guard, and feature export')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--train-normal-per-attack', type=int, default=50,
                        help='Target training normal:attack ratio (default 50:1). Only train is sampled.')
    parser.add_argument('--progress', type=int, default=1_000_000)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            run(normal_ratio=args.train_normal_per_attack, progress=args.progress)
    except (OSError, ValueError, csv.Error, TypeError, KeyError, RuntimeError) as exc:
        parser.exit(1, f'STOP: {exc}\n')


if __name__ == '__main__':
    main()
