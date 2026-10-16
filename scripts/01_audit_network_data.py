"""Read-only streaming CSV audit. Python 3.12 standard library only.

First-N mode is a parser/quality smoke check, NOT a representative sample.
Labels are reported as stored; no attack semantics or timestamps are invented.
"""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
import time

FILES = (
    'cicapt_IIOT_phase1_NetworkData.csv',
    'cicapt_IIOT_phase2_NetworkData.csv',
    'ton_iot_train_test_network.csv',
)
LABELS = ('label', 'type', 'subLabel', 'subLabelCat')
CHECK_FIELDS = ('ts', 'flow_duration', 'IAT', 'flow_idle_time',
                'flow_active_time', 'Number', 'rst_flag_number', 'rst_count')


def audit(path, limit):
    before = path.stat()
    started = time.monotonic()
    result = {
        'file': str(path.resolve()), 'size_bytes': before.st_size,
        'size_gib': round(before.st_size / 1024**3, 3),
        'requested_limit': limit, 'scope': 'first_N_records' if limit else 'full_file',
        'records_read': 0, 'valid_width_records': 0,
        'invalid_width_records': 0, 'invalid_width_examples': [],
        'complete_to_eof': False, 'error': None,
        'notes': [
            'No source files modified. No training, relabelling or deduplication.',
            'No session grouping, clock alignment or feature semantics validated.',
            'Timestamp values are numeric as stored; units/timezone are not assumed.',
            'Label counters are capped at 1000 distinct values per column.',
            'Numeric checks cover only the listed CHECK_FIELDS.',
        ],
    }
    counts, overflow, checks = {}, {}, {}
    previous_ts = None
    backward = equal = 0
    try:
        with path.open('r', encoding='utf-8-sig', newline='') as handle:
            reader = csv.reader(handle, strict=True)
            header = next(reader, None)
            if not header:
                raise ValueError('Missing CSV header')
            result['columns'] = header
            result['column_count'] = len(header)
            if len(header) != len(set(header)):
                raise ValueError('Duplicate column names; audit stopped')
            indexes = {name: i for i, name in enumerate(header)}
            counts = {name: Counter() for name in LABELS if name in indexes}
            overflow = {name: 0 for name in counts}
            checks = {name: {'finite': 0, 'missing': 0, 'invalid': 0,
                             'nonfinite': 0, 'negative': 0, 'zero': 0,
                             'minimum': None, 'maximum': None, 'first_values': []}
                      for name in CHECK_FIELDS if name in indexes}
            while not limit or result['records_read'] < limit:
                row = next(reader, None)
                if row is None:
                    result['complete_to_eof'] = True
                    result['scope'] = 'full_file'
                    break
                result['records_read'] += 1
                n = result['records_read']
                if len(row) != len(header):
                    result['invalid_width_records'] += 1
                    if len(result['invalid_width_examples']) < 5:
                        result['invalid_width_examples'].append(
                            {'record': n, 'physical_line_end': reader.line_num,
                             'actual_columns': len(row)})
                    previous_ts = None
                    continue
                result['valid_width_records'] += 1
                for name, counter in counts.items():
                    value = row[indexes[name]]
                    if value in counter or len(counter) < 1000:
                        counter[value] += 1
                    else:
                        overflow[name] += 1
                for name, stats in checks.items():
                    raw = row[indexes[name]]
                    if len(stats['first_values']) < 5:
                        stats['first_values'].append(raw)
                    value = None
                    if raw.strip().lower() in ('', '-', 'na', 'n/a', 'null', 'none'):
                        stats['missing'] += 1
                    else:
                        try:
                            parsed = Decimal(raw.strip())
                            if parsed.is_finite():
                                value = parsed
                            else:
                                stats['nonfinite'] += 1
                        except InvalidOperation:
                            stats['invalid'] += 1
                    if value is not None:
                        stats['finite'] += 1
                        stats['negative'] += int(value < 0)
                        stats['zero'] += int(value == 0)
                        if stats['minimum'] is None or value < stats['minimum']:
                            stats['minimum'] = value
                        if stats['maximum'] is None or value > stats['maximum']:
                            stats['maximum'] = value
                    if name == 'ts':
                        if value is not None and previous_ts is not None:
                            backward += int(value < previous_ts)
                            equal += int(value == previous_ts)
                        previous_ts = value
                if n % 250000 == 0:
                    print(f'  {path.name}: {n:,} records read', flush=True)
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    result['label_counts_raw_values'] = {k: dict(v) for k, v in counts.items()}
    result['label_overflow_records'] = overflow
    for stats in checks.values():
        for key in ('minimum', 'maximum'):
            if stats[key] is not None:
                stats[key] = str(stats[key])
    result['numeric_checks'] = checks
    result['timestamp_order'] = {
        'present': 'ts' in checks, 'adjacent_decreases': backward,
        'adjacent_equal': equal,
        'interpretation': 'File-order checks only; not proof of bad clocks or duplicate events.',
    }
    after = path.stat()
    result['source_unchanged_size_and_mtime'] = (
        before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns)
    result['elapsed_seconds'] = round(time.monotonic() - started, 2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', type=Path, default=Path('data/raw'))
    parser.add_argument('--out-dir', type=Path, default=Path('reports'))
    parser.add_argument('--limit', type=int, default=100000,
                        help='Records per file; default 100000, use 0 for full scan.')
    args = parser.parse_args()
    if args.limit < 0:
        parser.error('--limit must be nonnegative')
    paths = [args.raw_dir / name for name in FILES]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        parser.error('Missing input files: ' + ', '.join(missing))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    report = args.out_dir / f'network_audit_{stamp}.json'
    payload = {'audit_version': '1.0', 'created_utc': stamp, 'files': []}
    failed = False
    with report.open('x', encoding='utf-8') as output:
        for path in paths:
            print(f'\nAuditing {path.name} ...', flush=True)
            item = audit(path, args.limit)
            payload['files'].append(item)
            failed |= item['error'] is not None or not item['source_unchanged_size_and_mtime']
            print(f"  Scope: {item['scope']}; records: {item['records_read']:,}; "
                  f"invalid widths: {item['invalid_width_records']:,}")
            print('  Label counts:', item['label_counts_raw_values'].get('label', {}))
            if item['error']:
                print('  ERROR:', item['error'])
            output.seek(0)
            json.dump(payload, output, indent=2, ensure_ascii=False, allow_nan=False)
            output.truncate()
            output.flush()
    print(f'\nReport saved: {report.resolve()}')
    print('This audit does not certify that data are ready for model training.')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
