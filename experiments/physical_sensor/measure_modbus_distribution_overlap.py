"""Measure coarse histogram overlap between normal and attack Modbus rows."""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from apt_detection.physical_sensor.preprocessing import (  # noqa: E402
    FEATURE_COLUMNS,
    chronological_split,
    load_modbus_csv,
)

BINS = 32


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/raw/ton_iot/IoT_Modbus.csv"))
    parser.add_argument("--cutoff", default="2019-04-25")
    parser.add_argument("--output", type=Path, default=Path("docs/results/modbus_distribution_overlap.csv"))
    args = parser.parse_args()

    train, test = chronological_split(load_modbus_csv(args.data), args.cutoff)
    records = []
    for period, frame in (("train", train), ("test", test)):
        normal = frame.loc[frame["label"] == 0]
        attacks = frame.loc[frame["label"] == 1]
        for attack_type, attack_rows in attacks.groupby("type", sort=True):
            for feature in FEATURE_COLUMNS:
                normal_values = normal[feature].to_numpy(dtype=float)
                attack_values = attack_rows[feature].to_numpy(dtype=float)
                normal_hist, _ = np.histogram(normal_values, bins=BINS, range=(0, 65536))
                attack_hist, _ = np.histogram(attack_values, bins=BINS, range=(0, 65536))
                normal_share = normal_hist / len(normal_values)
                attack_share = attack_hist / len(attack_values)
                distance = 0.5 * np.abs(normal_share - attack_share).sum()
                records.append({
                    "period": period,
                    "attack_type": attack_type,
                    "feature": feature,
                    "histogram_bins": BINS,
                    "normal_rows": len(normal_values),
                    "attack_rows": len(attack_values),
                    "normal_mean": normal_values.mean(),
                    "attack_mean": attack_values.mean(),
                    "total_variation_distance": distance,
                    "histogram_overlap": 1 - distance,
                })

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(records).to_csv(output, index=False)
    print("Saved distribution-overlap report to {}".format(output))
    print("Distances compare normalized 32-bin histograms; attack type is used only for grouping.")


if __name__ == "__main__":
    main()
