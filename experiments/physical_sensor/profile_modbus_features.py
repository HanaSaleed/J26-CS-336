"""Summarize Modbus feature distributions by period and labeled group."""
import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from apt_detection.physical_sensor.preprocessing import (  # noqa: E402
    FEATURE_COLUMNS,
    chronological_split,
    load_modbus_csv,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/raw/ton_iot/IoT_Modbus.csv"))
    parser.add_argument("--cutoff", default="2019-04-25")
    parser.add_argument("--output", type=Path, default=Path("docs/results/modbus_feature_profile.csv"))
    args = parser.parse_args()

    train, test = chronological_split(load_modbus_csv(args.data), args.cutoff)
    profiles = []
    for period, frame in (("train", train), ("test", test)):
        groups = [("normal", frame.loc[frame["label"] == 0])]
        attacks = frame.loc[frame["label"] == 1]
        groups.extend(
            (attack_type, rows)
            for attack_type, rows in attacks.groupby("type", sort=True)
        )

        for group_name, rows in groups:
            for feature in FEATURE_COLUMNS:
                values = rows[feature]
                profiles.append({
                    "period": period,
                    "group": group_name,
                    "rows": len(rows),
                    "feature": feature,
                    "unique_values": values.nunique(),
                    "zero_fraction": (values == 0).mean(),
                    "mean": values.mean(),
                    "median": values.median(),
                    "p90": values.quantile(0.90),
                    "p99": values.quantile(0.99),
                    "max": values.max(),
                })

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(profiles).to_csv(output, index=False)
    print("Saved feature profile to {}".format(output))
    print("Attack type is used only to group this report, not as a model feature.")


if __name__ == "__main__":
    main()
