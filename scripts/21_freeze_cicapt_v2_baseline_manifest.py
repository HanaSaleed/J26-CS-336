#!/usr/bin/env python3
"""J26-CS-336 | Freeze the *allocation policy*, not the final test result.

Reads the existing v2 plan and preflight only. Does not read CICAPT data
rows, materialize datasets, train, or evaluate models. Treat the held-out
partition as an internal CICAPT holdout, not an independent APT campaign.

Usage from D:\\IIoT-APT-Research:
 .\\.venv\\Scripts\\python.exe .\\scripts\\21_freeze_cicapt_v2_baseline_manifest.py
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

PARTS = ('train', 'validation', 'test')
PLAN = Path('reports/cicapt_flow_split_plan_v2.json')
MAP = Path('reports/cicapt_positive_flow_split_v2.csv')
PREFLIGHT = Path('reports/cicapt_full_split_v2_preflight_fixed.json')
RAW = Path('data/raw/cicapt_IIOT_phase2_NetworkData.csv')
OUTPUT = Path('reports/cicapt_ip_packet_baseline_v2_manifest.json')
EXPECTED_ARP = 74995
EXPECTED_ATTACK = {'train':712, 'validation':146, 'test':146}


def sha256(path: Path) -> str:
    # Only small report files are hashed. Avoid rescanning the multi-GB raw file.
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    for file in (PLAN, MAP, PREFLIGHT, RAW):
        if not file.is_file():
            raise SystemExit(f'STOP: Missing required file: {file}')
    if OUTPUT.exists():
        raise SystemExit(f'STOP: Manifest already exists: {OUTPUT}. No overwrite.')
    plan = json.loads(PLAN.read_text(encoding='utf-8-sig'))
    preflight = json.loads(PREFLIGHT.read_text(encoding='utf-8-sig'))
    if 'PROVISIONAL' not in str(plan.get('version', '')):
        raise SystemExit('STOP: Unexpected v2 plan version')
    if int(preflight.get('total_raw_records', -1)) != 9536823:
        raise SystemExit('STOP: Raw record count differs from verified audit')
    if RAW.stat().st_size != int(preflight.get('source_bytes', -1)):
        raise SystemExit('STOP: Raw CSV file size has changed since preflight')
    if sha256(MAP) != preflight.get('positive_mapping_sha256'):
        raise SystemExit('STOP: Positive v2 mapping changed since full preflight')
    if int(preflight.get('positive_flow_keys_verified', -1)) != 46:
        raise SystemExit('STOP: Expected 46 attack-bearing flow groups')
    if int(preflight.get('positive_observations_verified', -1)) != 1004:
        raise SystemExit('STOP: Expected 1,004 positive observations')

    positive_counts = Counter()
    group_counts = Counter()
    with MAP.open('r', encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        required = {'canonical_flow_key','proposed_split','attack_records','category_counts_json'}
        if not required.issubset(reader.fieldnames or []):
            raise SystemExit('STOP: Unexpected positive mapping schema')
        seen = set()
        for row in reader:
            key = row['canonical_flow_key']
            split = row['proposed_split']
            if key in seen or split not in PARTS:
                raise SystemExit('STOP: Duplicate flow key or invalid split in v2 mapping')
            seen.add(key)
            n = int(row['attack_records'])
            if n < 1 or sum(map(int, json.loads(row['category_counts_json']).values())) != n:
                raise SystemExit('STOP: Invalid positive-group counts')
            positive_counts[split] += n
            group_counts[split] += 1
    if len(seen) != 46 or any(positive_counts[p] != EXPECTED_ATTACK[p] for p in PARTS):
        raise SystemExit('STOP: Positive split totals no longer match verified v2 result')

    pre_by = preflight['counts_by_split']
    arp_by_split = {p: int(pre_by[p]['benign_rows_with_non_ip_address_tokens']) for p in PARTS}
    if sum(arp_by_split.values()) != EXPECTED_ARP:
        raise SystemExit('STOP: Non-IP record count changed since full preflight')
    if arp_by_split != {'train':EXPECTED_ARP, 'validation':0, 'test':0}:
        raise SystemExit('STOP: Unexpected non-IP assignment; review exclusion policy')

    by_split = {}
    for part in PARTS:
        raw_normal = int(pre_by[part]['normal'])
        attacks = int(pre_by[part]['attack'])
        if attacks != EXPECTED_ATTACK[part]:
            raise SystemExit(f'STOP: Unexpected attack total for {part}')
        eligible_normal = raw_normal - arp_by_split[part]
        by_split[part] = {
            'eligible_normal_records': eligible_normal,
            'attack_labeled_records': attacks,
            'eligible_total_records': eligible_normal + attacks,
            'attack_rate_percent': round(100 * attacks / (eligible_normal + attacks), 8),
            'positive_five_tuple_groups': group_counts[part],
            'normal_records_in_attack_containing_groups': int(pre_by[part]['benign_rows_in_positive_containing_flows']),
        }
    eligible_total = sum(v['eligible_total_records'] for v in by_split.values())
    if eligible_total != 9461828:
        raise SystemExit(f'STOP: Unexpected proposed eligible count: {eligible_total}')

    manifest = {
        'project': 'J26-CS-336',
        'name': 'CICAPT Phase2 IP-addressed packet-level exploratory baseline (v2)',
        'status': 'FROZEN ALLOCATION POLICY FOR EXPLORATORY BASELINE; TRAINING DATA NOT MATERIALIZED',
        'not_a_claim_of': ['independent APT-campaign evaluation', 'verified packet-to-PCAP provenance', 'ready-to-deploy Raspberry Pi window feature compatibility'],
        'raw_source': {'path':str(RAW), 'bytes':RAW.stat().st_size, 'total_records':9536823,
                       'note':'Raw file size checked against preflight. No full-file checksum computed; original file unchanged.'},
        'source_artifacts_sha256': {str(p):sha256(p) for p in (PLAN, MAP, PREFLIGHT)},
        'ip_scope_note': 'Original full preflight accepts valid IPv4 OR IPv6 addresses; this manifest counts IP-addressed candidates, not independently verified IPv4-only records.',
        'label_policy': 'Use publisher-provided label as target; never include label, subLabel, subLabelCat, Caldera event candidate, raw IPs, or epoch ts in features.',
        'eligibility_policy': {
            'excluded_record_count':EXPECTED_ARP,
            'excluded_record_type':'Source IP=0, Destination IP=0, Protocol Type=0, ARP=1, IPv=0, label=0',
            'evidence':'Full Phase2 terminal check on 2026-10-20; all 74,995 zero-address records had this pattern.',
            'method':'Keep source rows untouched; skip these only for the IP-addressed baseline materialization.',
            'warning':'The non-IP fallback group in preflight was only for accounting; never use it as a real flow.'
        },
        'split_policy': {
            'unit':'canonical bidirectional IP/port/protocol 5-tuple; groups may include both benign and attack observations',
            'attack_bearing_groups':'Use explicit v2 positive-flow mapping (46 groups)',
            'benign_only_groups':'Hash flow key using BLAKE2b digest_size=8 on J26-CS-336|CICAPT|flow-v1|<canonical_key>; train if fraction <0.70, validation if <0.85, else test',
            'design_used_known_attack_categories':True,
            'limitation':'Flow disjointness does not ensure session/campaign disjointness; validation attacks occur only Dec2; test covers 5 of 25 observed categories.',
            'use':'Train and tune on train/validation only; defer opening test examples until choices are locked. Report test once and label it internal CICAPT holdout.'
        },
        'counts_by_split_after_arp_exclusion':by_split,
        'totals': {'eligible_ip_addressed_candidate_records':eligible_total, 'attack_labeled_records':1004,
                   'normal_eligible_records':eligible_total-1004, 'attack_flow_keys':46},
        'next': 'Implement streaming packet-level baseline preprocessing and train/validation pipeline. Confirm IPv4-only vs IPv6 presence before asserting an IPv4-only experiment. Do not treat dataset columns as verified 5/10/15/20-second gateway windows.'
    }
    # Only reports are written; raw data, mapping, and original labels are unchanged.
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open('x', encoding='utf-8') as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=False)
        stream.write('\n')

    print('=== CICAPT v2 EXPLORATORY BASELINE MANIFEST ===')
    print('Group/label checks: PASS')
    print('Raw bytes / mapping SHA256 checks: PASS')
    print('Verified benign ARP exclusions: 74,995')
    print('PARTITION       NORMAL       ATTACK       TOTAL')
    for p in PARTS:
        c = by_split[p]
        print(f'{p:<12} {c["eligible_normal_records"]:>10,} {c["attack_labeled_records"]:>11,} {c["eligible_total_records"]:>11,}')
    print(f'Eligible total: {eligible_total:,}')
    print(f'Manifest: {OUTPUT}')
    print('No raw CSV changed, no split files materialized, no model/test evaluation.')


if __name__ == '__main__':
    main()
