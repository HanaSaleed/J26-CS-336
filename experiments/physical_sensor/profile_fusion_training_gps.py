"""Describe GPS coordinates by binary label and date in fusion training rows."""
import argparse
from pathlib import Path

import pandas as pd

from compare_sensor_fusion import aggregate_sensor
from compare_telemetry_sensors import DATASETS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw/ton_iot"))
    parser.add_argument("--cutoff", default="2019-04-26",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/ton_iot_sensor_fusion_training_gps_by_label.csv"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    data_dir = args.data_dir if args.data_dir.is_absolute() else root / args.data_dir

    per_sensor = {
        name: aggregate_sensor(name, config, data_dir)[0]
        for name, config in DATASETS.items()
    }
    feature_tables = [table.drop(columns="label") for table in per_sensor.values()]
    shared_features = pd.concat(feature_tables, axis=1, join="inner").sort_index()
    label_tables = pd.concat(
        [table["label"].rename(name) for name, table in per_sensor.items()],
        axis=1,
        join="inner",
    ).sort_index()
    if label_tables.nunique(axis=1).gt(1).any():
        raise ValueError("Sensor labels disagree on shared timestamp seconds.")

    frame = shared_features[["gps_tracker__latitude", "gps_tracker__longitude"]].copy()
    frame["label"] = label_tables.iloc[:, 0].astype(int)
    cutoff = pd.Timestamp(args.cutoff).normalize()
    frame = frame.loc[frame.index.normalize() <= cutoff].copy()
    frame["date"] = frame.index.strftime("%Y-%m-%d")

    rows = []
    for label, group in frame.groupby("label", sort=True):
        for feature in ("gps_tracker__latitude", "gps_tracker__longitude"):
            values = group[feature].dropna()
            rows.append({
                "label": int(label),
                "class_name": "normal" if label == 0 else "attack",
                "feature": feature,
                "rows": len(values),
                "unique_values": int(values.nunique()),
                "mean": float(values.mean()),
                "std": float(values.std()),
                "minimum": float(values.min()),
                "p10": float(values.quantile(0.10)),
                "p25": float(values.quantile(0.25)),
                "median": float(values.median()),
                "p75": float(values.quantile(0.75)),
                "p90": float(values.quantile(0.90)),
                "maximum": float(values.max()),
            })
    label_output = args.output if args.output.is_absolute() else root / args.output
    daily_output = label_output.with_name("ton_iot_sensor_fusion_training_gps_by_day.csv")
    label_output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(label_output, index=False)

    daily = frame.groupby(["date", "label"], sort=True).agg(
        rows=("gps_tracker__latitude", "size"),
        latitude_mean=("gps_tracker__latitude", "mean"),
        latitude_median=("gps_tracker__latitude", "median"),
        longitude_mean=("gps_tracker__longitude", "mean"),
        longitude_median=("gps_tracker__longitude", "median"),
    ).reset_index()
    daily["class_name"] = daily["label"].map({0: "normal", 1: "attack"})
    daily.to_csv(daily_output, index=False)
    print("Matched training seconds: {} (normal={}, attack={})".format(
        len(frame), int(frame["label"].eq(0).sum()), int(frame["label"].eq(1).sum())
    ))
    print("By-label GPS profile saved to {}".format(label_output))
    print("By-day GPS profile saved to {}".format(daily_output))
    print("Profile uses training rows only; no holdout results were evaluated.")


if __name__ == "__main__":
    main()
