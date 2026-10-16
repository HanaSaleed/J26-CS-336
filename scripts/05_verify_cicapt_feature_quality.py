#!/usr/bin/env python3
r"""J26-CS-336 | Step 5.9: read-only, bounded CICAPT Phase 2 feature audit.

Checks column value patterns to guide feature selection. Does not modify data,
relabel traffic, infer causality, or claim publisher source code exactly matches
this particular dataset export.

Usage (Windows PowerShell):
  .\.venv\Scripts\python.exe .\scripts\05_verify_cicapt_feature_quality.py --sample 100000
"""

from __future__ import annotations

import argparse
import csv
import math
from collections import Counter
from pathlib import Path


CHECK_FIELDS = (
    'ts', 'IAT', 'flow_idle_time', 'max_duration', 'min_duration',
    'average_duration', 'flow_duration', 'flow_active_time',
    'Duration', 'Header_Length', 'Tot size', 'Number',
    'ack_flag_number', 'rst_flag_number', 'fin_flag_number',
    'psh_flag_number', 'syn_flag_number',
    'ack_count', 'rst_count', 'fin_count', 'urg_count', 'syn_count',
    'label',
)


def number(raw: str | None) -> float | None:
    try:
        value = float(raw)  # Do not convert any field before validating it.
        return value if math.isfinite(value) else None
    except (ValueError, TypeError, OverflowError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description='CICAPT Phase 2 limited read-only feature quality check')
    parser.add_argument('--sample', type=int, default=100_000, help='First N records; at most 100,000')
    parser.add_argument('--project-root', type=Path, default=None, help='Optional root override for testing')
    args = parser.parse_args()
    if not 1 <= args.sample <= 100_000:
        parser.error('--sample must be between 1 and 100000')
    root = args.project_root or Path(__file__).resolve().parent.parent
    path = root / 'data' / 'raw' / 'cicapt_IIOT_phase2_NetworkData.csv'
    if not path.is_file():
        parser.error(f'CSV not found: {path}')

    checked = Counter()
    values = Counter()
    labels = Counter()
    ttl_like = Counter()
    few_examples = []
    rows = 0
    with path.open('r', encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        missing = set(CHECK_FIELDS) - set(reader.fieldnames or [])
        if missing:
            parser.error(f'Missing required columns: {sorted(missing)}')
        for record in reader:
            if rows >= args.sample:
                break
            rows += 1
            labels[record['label'].strip()] += 1
            v = {field: number(record[field]) for field in CHECK_FIELDS if field != 'label'}
            for field, val in v.items():
                if val is not None:
                    checked[field] += 1
            ts = v['ts']
            if ts is not None:
                for field in ('IAT','flow_idle_time','max_duration','min_duration','average_duration'):
                    x = v[field]
                    if x is not None:
                        if abs(x) > 1_000_000_000:
                            values[f'{field}_over_1e9'] += 1
                        if abs(x - ts) < .001:
                            values[f'{field}_close_to_ts'] += 1
            if v['flow_duration'] is not None and v['flow_active_time'] is not None:
                if math.isclose(v['flow_duration'], v['flow_active_time'], rel_tol=1e-10, abs_tol=1e-8):
                    values['flow_active_equal_duration'] += 1
            if v['Number'] is not None:
                if 0 <= v['Number'] <= 19:
                    values['Number_0_to_19'] += 1
            if v['Duration'] is not None and v['Duration'].is_integer():
                ttl_like[int(v['Duration'])] += 1
            if v['rst_count'] is not None and v['rst_flag_number'] is not None and v['ack_flag_number'] is not None:
                if v['rst_count'] > 0 and v['rst_flag_number'] == 0 and v['ack_flag_number'] == 1:
                    values['rst_count_pos_R_flag_0_A_flag_1'] += 1
            if v['ack_count'] is not None and v['fin_flag_number'] is not None:
                if v['ack_count'] > 0 and v['fin_flag_number'] == 1:
                    values['ack_count_pos_F_flag_1'] += 1
            if record['label'].strip() == '1' and len(few_examples) < 3:
                few_examples.append({
                    'row': rows,
                    'ack_flag_number': record['ack_flag_number'],
                    'rst_flag_number': record['rst_flag_number'],
                    'fin_flag_number': record['fin_flag_number'],
                    'ack_count': record['ack_count'],
                    'rst_count': record['rst_count'],
                    'fin_count': record['fin_count'],
                    'Duration': record['Duration'],
                    'Header_Length': record['Header_Length'],
                    'Tot size': record['Tot size'],
                })

    print('=== CICAPT FEATURE QUALITY PROBE (READ ONLY) ===')
    print(f'CSV: {path}')
    print(f'Rows checked: {rows:,} (FIRST rows only; not whole dataset)')
    print(f'Label counts in sample: {dict(labels)}')
    print('\n=== TIME-FEATURE PATTERNS ===')
    for field in ('IAT','flow_idle_time','max_duration','min_duration','average_duration'):
        denom = checked[field]
        print(f'{field:>18}: >1e9={values[f"{field}_over_1e9"]:,}/{denom:,}; '
              f'close_to_ts={values[f"{field}_close_to_ts"]:,}/{denom:,}')
    print(f'flow_active_time equal to flow_duration: '
          f'{values["flow_active_equal_duration"]:,}/{min(checked["flow_active_time"], checked["flow_duration"]):,}')
    print(f'Number between 0 and 19: {values["Number_0_to_19"]:,}/{checked["Number"]:,}')
    print('\n=== Duration FIELD (TOP OBSERVED INTEGER VALUES) ===')
    print('The uploaded Connectivity_features.py computes Duration from IP TTL;')
    print('these values help CHECK plausibility, not prove the exact exported data generation.')
    print('Most common values:', ttl_like.most_common(12))
    print('\n=== TCP FLAG / COUNTER CONSISTENCY SCREEN ===')
    print('Rows with rst_count>0, current RST flag=0 and current ACK flag=1:',
          f'{values["rst_count_pos_R_flag_0_A_flag_1"]:,}')
    print('Rows with ack_count>0 and current FIN flag=1:',
          f'{values["ack_count_pos_F_flag_1"]:,}')
    print('CAUTION: Flow counts are cumulative; an individual current flag')
    print('need not equal its cumulative count. Neither metric proves a mapping bug.')
    print('However, the uploaded Supporting_functions.py maps FIN->ack_count,')
    print('RST->fin_count, PSH->urg_count, ACK->rst_count in compare_flow_flags().')
    print('Treat these source names as suspect until matched to the CSV export.')
    print('\n=== FIRST LABELED ROW EXAMPLES (IF PRESENT) ===')
    if not few_examples:
        print('None in first N records; this does not mean the full file lacks attacks.')
    for example in few_examples:
        print(example)
    print('\n=== RECOMMENDATION ===')
    print('Keep ORIGINAL CSV files unchanged. Do not use raw time fields,')
    print('misnamed counters, IP identifiers, or label columns as model inputs yet.')
    print('Next: document provisional feature exclusions and define reproducible')
    print('packet/window features for 5/10/15/20-second simulation measurements.')


if __name__ == '__main__':
    main()
