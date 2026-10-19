"""Audit possible Modbus time partitions and prior exposure to each period."""
import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from apt_detection.physical_sensor.preprocessing import load_modbus_csv  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/raw/ton_iot/IoT_Modbus.csv"))
    parser.add_argument("--fit-through", default="2019-04-23")
    parser.add_argument("--validation-through", default="2019-04-25")
    parser.add_argument("--output", type=Path, default=Path("docs/results/modbus_split_feasibility.csv"))
    args = parser.parse_args()

    frame = load_modbus_csv(args.data)
    fit_end = pd.Timestamp(args.fit_through).normalize()
    validation_end = pd.Timestamp(args.validation_through).normalize()
    if validation_end <= fit_end:
        raise ValueError("Validation end must be after the fit cutoff.")

    day = frame["timestamp"].dt.normalize()
    partitions = [
        ("candidate_fit_period", frame.loc[day <= fit_end]),
        ("candidate_validation_already_used_in_prior_training",
         frame.loc[(day > fit_end) & (day <= validation_end)]),
        ("previously_examined_test_period", frame.loc[day > validation_end]),
    ]
    records = []
    for name, rows in partitions:
        attacks = rows.loc[rows["label"] == 1, "type"].value_counts().sort_index()
        records.append({
            "partition": name,
            "start": rows["timestamp"].min(),
            "end": rows["timestamp"].max(),
            "rows": len(rows),
            "normal": int((rows["label"] == 0).sum()),
            "attack": int((rows["label"] == 1).sum()),
            "attack_type_counts": "; ".join(
                "{}={}".format(kind, count) for kind, count in attacks.items()
            ),
        })

    fit, validation, _ = [rows for _, rows in partitions]
    if set(fit["label"]) != {0, 1} or set(validation["label"]) != {0, 1}:
        raise ValueError("Candidate fit and validation periods must each contain both labels.")
    if set(fit["timestamp"]) & set(validation["timestamp"]):
        raise ValueError("A timestamp appears in both candidate periods.")

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    report = pd.DataFrame(records)
    report.to_csv(output, index=False)
    print(report.to_string(index=False))
    print("Saved split-feasibility report to {}".format(output))
    print("Warning: the candidate validation dates were included in prior model training.")
    print("The later test dates were also examined; neither period is an untouched final test.")


if __name__ == "__main__":
    main()
