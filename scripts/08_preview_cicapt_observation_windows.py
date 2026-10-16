r"""J26-CS-336: READ-ONLY, exploratory CICAPT CSV observation-window preview.

IMPORTANT: A CICAPT CSV *row* is NOT established to be one original packet.
Therefore, this script deliberately does NOT import PacketEvent/window_stream,
does NOT label an attack window, and does NOT write ML training records.
It summarizes a bounded first-N-row sample for schema and window compatibility.

Run from project root:
  .\.venv\Scripts\python.exe .\scripts\08_preview_cicapt_observation_windows.py --sample 100000
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
import math
from pathlib import Path

REQUIRED = (
    'ts', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port',
    'Protocol Type', 'Tot size', 'fin_flag_number', 'syn_flag_number',
    'rst_flag_number', 'psh_flag_number', 'ack_flag_number', 'urg_flag_number',
    'ece_flag_number', 'cwr_flag_number', 'label', 'subLabel', 'subLabelCat',
)
FLAGS = ('fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr')
WINDOWS = (5, 10, 15, 20)


@dataclass(frozen=True)
class Observation:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    exported_size: int
    flags: tuple[int, ...]
    label: str


def as_integer(s: str, name: str, lo: int, hi: int) -> int:
    try:
        number = Decimal(s.strip())
    except InvalidOperation as exc:
        raise ValueError(f'{name} is not numeric: {s!r}') from exc
    if not number.is_finite() or number != number.to_integral_value():
        raise ValueError(f'{name} is not a finite integer: {s!r}')
    value = int(number)
    if not lo <= value <= hi:
        raise ValueError(f'{name} outside [{lo}, {hi}]: {value}')
    return value


def from_csv_record(row: dict[str, str]) -> Observation:
    ts = float(row['ts'])
    if not math.isfinite(ts) or ts <= 0:
        raise ValueError(f'Invalid timestamp: {row["ts"]!r}')
    # Guard Python's datetime range as well.
    datetime.fromtimestamp(ts, tz=timezone.utc)
    source = row['Source IP'].strip()
    dest = row['Destination IP'].strip()
    if not source or not dest:
        raise ValueError('Missing IP address')
    size = as_integer(row['Tot size'], 'Tot size', 1, 65535)
    flags = tuple(as_integer(row[f'{flag}_flag_number'], flag, 0, 1) for flag in FLAGS)
    label = row['label'].strip()
    if label not in ('0', '1'):
        raise ValueError(f'Unsupported label: {label!r}')
    return Observation(
        ts, source, dest,
        as_integer(row['Source Port'], 'Source Port', 0, 65535),
        as_integer(row['Destination Port'], 'Destination Port', 0, 65535),
        as_integer(row['Protocol Type'], 'Protocol Type', 0, 255),
        size, flags, label,
    )


def read_first_n(path: Path, limit: int) -> tuple[list[Observation], Counter, int]:
    observations: list[Observation] = []
    labels: Counter = Counter()
    decreases = 0
    previous = None
    with path.open('r', encoding='utf-8-sig', newline='') as file:
        reader = csv.DictReader(file)
        if reader.fieldnames is None:
            raise ValueError('CSV is empty')
        missing = [col for col in REQUIRED if col not in reader.fieldnames]
        if missing:
            raise ValueError(f'Missing required columns: {missing}')
        for index, row in enumerate(reader, start=1):
            if index > limit:
                break
            try:
                obs = from_csv_record(row)
            except (ValueError, TypeError, OverflowError, KeyError) as exc:
                raise ValueError(f'Invalid first-N observation in CSV record {index}: {exc}') from exc
            observations.append(obs)
            labels[obs.label] += 1
            if previous is not None and obs.ts < previous:
                decreases += 1
            previous = obs.ts
    return observations, labels, decreases


@dataclass
class WindowPreview:
    observation_rows: int = 0
    sum_exported_size_values: int = 0
    attack_labeled_rows: int = 0
    destination_ports: set[int] = field(default_factory=set)
    directed_pairs: set[tuple[str, str]] = field(default_factory=set)

    def add(self, row: Observation) -> None:
        self.observation_rows += 1
        self.sum_exported_size_values += row.exported_size
        self.attack_labeled_rows += row.label == '1'
        self.destination_ports.add(row.dst_port)
        self.directed_pairs.add((row.src_ip, row.dst_ip))


def windows_for(observations: list[Observation], seconds: int) -> dict[tuple[int, str], WindowPreview]:
    """Group per source IP purely for exploration; not the final asset attribution."""
    if seconds not in WINDOWS:
        raise ValueError('Unsupported duration')
    groups: dict[tuple[int, str], WindowPreview] = {}
    for row in observations:
        key = (math.floor(row.ts / seconds) * seconds, row.src_ip)
        groups.setdefault(key, WindowPreview()).add(row)
    return groups


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample', type=int, default=100000,
                        help='First N exported CSV records (default 100000; max 200000)')
    parser.add_argument('--csv', type=Path, default=None,
                        help='Optional CSV path; default Phase 2 in this research folder')
    args = parser.parse_args()
    if not 1 <= args.sample <= 200000:
        parser.error('--sample must be from 1 to 200000')

    root = Path(__file__).resolve().parents[1]
    path = args.csv or (root / 'data' / 'raw' / 'cicapt_IIOT_phase2_NetworkData.csv')
    if not path.is_file():
        parser.error(f'CSV not found: {path}')

    print('=== CICAPT OBSERVATION-WINDOW PREVIEW (READ ONLY) ===')
    print('IMPORTANT: row != verified original packet; output is NOT training data.')
    print('CSV:', path)
    observations, labels, decreases = read_first_n(path, args.sample)
    print('CSV rows inspected:', len(observations))
    print('Exported label counts:', dict(sorted(labels.items())))
    print('Backward timestamp jumps in file order:', decreases)
    if not observations:
        print('No rows available.'); return
    print('Sample minimum UTC:', utc(min(o.ts for o in observations)))
    print('Sample maximum UTC:', utc(max(o.ts for o in observations)))
    print('Protocol counts:', dict(sorted(Counter(o.protocol for o in observations).items())))
    print('Note: previews group by observed SOURCE IP, not confirmed device ID.')
    print('Note: sorting/grouping is within the first-N-row sample only.')

    for seconds in WINDOWS:
        windows = windows_for(observations, seconds)
        label_windows = [(k, v) for k, v in windows.items() if v.attack_labeled_rows]
        print(f'\n=== {seconds}-SECOND EXPLORATORY WINDOWS ===')
        print('Nonempty source-IP/window groups:', len(windows))
        print('Source CSV rows accounted for:', sum(v.observation_rows for v in windows.values()))
        print('Groups containing at least one dataset attack-labeled row:', len(label_windows))
        examples = sorted(label_windows, key=lambda kv: kv[0])[:3]
        if not examples:
            examples = sorted(windows.items(), key=lambda kv: kv[0])[:2]
        for (start, src), v in examples:
            print(f'  {utc(start)} to {utc(start + seconds)} '
                  f'from={src} observed_rows={v.observation_rows} '
                  f'sum_exported_sizes={v.sum_exported_size_values} '
                  f'attack_labeled_rows={v.attack_labeled_rows} '
                  f'unique_dst_ports={len(v.destination_ports)}')

    print('\n=== INTERPRETATION ===')
    print('PASS: Read selected columns and construct four exploratory UTC window views.')
    print('NOT VERIFIED: one row = one original packet, complete windows, true packet counts,')
    print('attack window ground truth, flow labels, or deployment-ready ML features.')
    print('No file was written or modified. Do not train on these previews.')


if __name__ == '__main__':
    main()
