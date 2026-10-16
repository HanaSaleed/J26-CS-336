#!/usr/bin/env python3
"""J26-CS-336: read-only, bounded CICAPT Phase 2 attack-label context inspection.

What it does:
- Read the CICAPT attack metadata (Time of Attack, tactic, technique).
- Read ONLY the first --sample Phase 2 network rows (max 100,000).
- Report every attack-labeled row's endpoints and nearest metadata event.
- Summarize benign rows occurring near the attack-labeled sample records.

What it does NOT do:
- Modify files, re-label packets, train a classifier, or establish causal labels.

Run from D:\\IIoT-APT-Research:
  .\\.venv\\Scripts\\python.exe .\\scripts\\04_inspect_cicapt_attack_context.py
"""

import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def parse_number(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def utc(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def normalize(value):
    return str(value or '').strip().casefold()


def endpoint(ip, port):
    return f'{ip}:{port}'


def main():
    parser = argparse.ArgumentParser(description='Read-only CICAPT labelled-row context probe')
    parser.add_argument('--sample', type=int, default=100_000, help='First N rows, max 100000')
    parser.add_argument('--context-seconds', type=int, default=60, help='Benign-record context around labelled rows')
    parser.add_argument('--project-root', type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.sample <= 100_000:
        parser.error('--sample must be from 1 to 100000')
    if not 0 <= args.context_seconds <= 3600:
        parser.error('--context-seconds must be from 0 to 3600')

    root = args.project_root or Path(__file__).resolve().parent.parent
    metadata_path = root / 'data' / 'metadata' / 'cicapt' / 'attack_info.csv'
    phase2_path = root / 'data' / 'raw' / 'cicapt_IIOT_phase2_NetworkData.csv'
    if not metadata_path.is_file() or not phase2_path.is_file():
        parser.error(f'Missing file(s): {metadata_path} or {phase2_path}')

    with metadata_path.open('r', encoding='utf-8-sig', newline='') as file:
        metadata_reader = csv.DictReader(file)
        print('=== METADATA FIELDS ===')
        print(', '.join(metadata_reader.fieldnames or []))
        events = []
        for item in metadata_reader:
            t = parse_number(item.get('Time of Attack'))
            if t is not None:
                events.append((t, normalize(item.get('Tactic Name')), normalize(item.get('Technique Name'))))
    if not events:
        parser.error('Metadata contains no readable Time of Attack values')
    print(f'Metadata events: {len(events)}')
    print('Important: attack_info.csv gives a timestamp, tactic, technique, and PID;')
    print('it does not supply per-packet source/destination IPs or attack end times.\n')

    positives = []
    benign = []
    label_counts = Counter()
    read_count = 0
    required = {'ts','label','subLabel','subLabelCat','Source IP','Destination IP',
                'Source Port','Destination Port','Protocol Type'}
    with phase2_path.open('r', encoding='utf-8-sig', newline='') as file:
        reader = csv.DictReader(file)
        missing = required - set(reader.fieldnames or [])
        if missing:
            parser.error(f'Missing Phase 2 columns: {sorted(missing)}')
        for item in reader:
            if read_count >= args.sample:
                break
            read_count += 1
            label = normalize(item['label'])
            label_counts[label] += 1
            t = parse_number(item['ts'])
            if t is None:
                continue
            record = {
                'row': read_count, 'ts': t,
                'src': item['Source IP'].strip(), 'dst': item['Destination IP'].strip(),
                'sport': item['Source Port'].strip(), 'dport': item['Destination Port'].strip(),
                'protocol': item['Protocol Type'].strip(),
                'tactic': normalize(item['subLabel']),
                'technique': normalize(item['subLabelCat'])
            }
            if label == '1':
                positives.append(record)
            elif label == '0':
                benign.append((t, record['src'], record['dst']))

    print('=== SAMPLE COUNTS ===')
    print(f'Rows checked: {read_count:,} (first rows only; not full data)')
    print('Label counts:', dict(label_counts))
    print(f'Attack-labeled rows: {len(positives)}')
    if not positives:
        print('No labelled attacks in this sample. Stop here; do not infer anything about the full dataset.')
        return

    print('\n=== ATTACK-LABELED NETWORK ROWS ===')
    groups = defaultdict(list)
    matches = 0
    for p in positives:
        event = min(events, key=lambda x: abs(x[0] - p['ts']))
        delta = p['ts'] - event[0]
        match = (p['tactic'],p['technique']) == (event[1], event[2])
        matches += int(match)
        groups[(p['tactic'],p['technique'])].append(p)
        print(f"row={p['row']:>6,}  {utc(p['ts'])}  "
              f"{endpoint(p['src'], p['sport'])} -> {endpoint(p['dst'], p['dport'])} "
              f"proto={p['protocol']}  delta_to_nearest_event={delta:+.1f}s  labels_match={match}")
    print(f'Nearest-event tactic/technique text matches: {matches}/{len(positives)}')

    print('\n=== LABELLED ENDPOINT SUMMARY ===')
    print('Protocol counts:', dict(Counter(p['protocol'] for p in positives)))
    print('Source IP counts:', dict(Counter(p['src'] for p in positives)))
    print('Destination IP counts:', dict(Counter(p['dst'] for p in positives)))
    print('Destination port counts:', dict(Counter(p['dport'] for p in positives)))
    print('Descriptions:', dict(Counter((p['tactic'],p['technique']) for p in positives)))

    print('\n=== SURROUNDING NORMAL-LABELED RECORDS ===')
    c = args.context_seconds
    for (tactic, technique), records in groups.items():
        first = min(p['ts'] for p in records)
        last = max(p['ts'] for p in records)
        positive_pairs = {(p['src'], p['dst']) for p in records}
        surrounding = [(ts,src,dst) for ts,src,dst in benign if first-c <= ts <= last+c]
        same_pairs = sum((src,dst) in positive_pairs for _,src,dst in surrounding)
        print(f'{tactic} / {technique}:')
        print(f'  labelled rows={len(records)}, labelled span={utc(first)} to {utc(last)}')
        print(f'  normal-labelled rows within +/-{c}s of labelled span: {len(surrounding):,}')
        print(f'  of those, same directed IP pair as labelled rows: {same_pairs:,}')
    print('\nInterpretation: normal-labelled neighboring records are not proof of clean traffic,')
    print('and matching attack event labels do not prove a packet caused an attack.')
    print('No source files were modified; no rows after the requested sample were read.')


if __name__ == '__main__':
    main()
