"""Evaluate a chronological TON_IoT Weather sensor baseline."""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from apt_detection.physical_sensor.evaluate import evaluate_binary  # noqa: E402
from apt_detection.physical_sensor.predict import predict_attack_probability  # noqa: E402
from apt_detection.physical_sensor.train import fit_baseline  # noqa: E402

FEATURE_COLUMNS = ["temperature", "pressure", "humidity"]
REQUIRED_COLUMNS = ["date", "time", "label", "type", *FEATURE_COLUMNS]
DEFAULT_DATA = Path("data/raw/ton_iot/IoT_Weather.csv")


def load_weather_csv(path):
    """Load and validate the processed Weather CSV without changing it."""
    frame = pd.read_csv(Path(path))
    missing_columns = sorted(set(REQUIRED_COLUMNS) - set(frame.columns))
    if missing_columns:
        raise ValueError("Missing required columns: {}".format(missing_columns))

    date = frame["date"].astype(str).str.strip()
    clock = frame["time"].astype(str).str.strip()
    frame["timestamp"] = pd.to_datetime(
        date + " " + clock,
        format="%d-%b-%y %H:%M:%S",
        errors="coerce",
    )
    if frame["timestamp"].isna().any():
        raise ValueError("Some date/time values could not be parsed.")

    for column in FEATURE_COLUMNS + ["label"]:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")
    if frame[FEATURE_COLUMNS + ["label"]].isna().any().any():
        raise ValueError("Missing or nonnumeric model values found.")
    frame["label"] = frame["label"].astype(int)
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("Expected binary label values 0 and 1.")

    frame["type"] = frame["type"].astype(str).str.strip()
    return frame


def split_chronologically(frame, cutoff_date):
    """Train through cutoff_date and evaluate only on later dates."""
    cutoff = pd.Timestamp(cutoff_date).normalize()
    day = frame["timestamp"].dt.normalize()
    train = frame.loc[day <= cutoff].copy()
    test = frame.loc[day > cutoff].copy()
    if train.empty or test.empty:
        raise ValueError("The cutoff produced an empty train or test partition.")
    if set(train["label"]) != {0, 1} or set(test["label"]) != {0, 1}:
        raise ValueError("Both labels must occur in both partitions.")
    return train, test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--cutoff", default="2019-04-26",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/weather_model_comparison.csv"))
    args = parser.parse_args()

    frame = load_weather_csv(args.data)
    train, test = split_chronologically(frame, args.cutoff)
    model = fit_baseline(train, FEATURE_COLUMNS)
    probability = predict_attack_probability(model, test, FEATURE_COLUMNS)
    metrics = evaluate_binary(test["label"], probability)
    predicted_attack = probability >= 0.5

    record = {
        "model": "standardized_logistic_regression",
        "dataset": "TON_IoT_Weather",
        "split": "chronological_exploratory_holdout",
        "cutoff_inclusive": args.cutoff,
        "features": ";".join(FEATURE_COLUMNS),
        "train_rows": len(train),
        "train_normal": int((train["label"] == 0).sum()),
        "train_attack": int((train["label"] == 1).sum()),
        "test_rows": len(test),
        "test_normal": int((test["label"] == 0).sum()),
        "test_attack": int((test["label"] == 1).sum()),
        **metrics,
    }

    attack_rows = test.loc[test["label"] == 1, "type"].reset_index(drop=True)
    attack_detected = predicted_attack[test["label"].eq(1).to_numpy()]
    type_frame = pd.DataFrame({"type": attack_rows, "detected": attack_detected})
    by_type = []
    for attack_type, group in type_frame.groupby("type", sort=True):
        detected = int(group["detected"].sum())
        by_type.append({
            "model": record["model"],
            "attack_type": attack_type,
            "attack_rows": len(group),
            "detected": detected,
            "missed": len(group) - detected,
            "recall": detected / len(group),
        })

    normal = test.loc[test["label"] == 0, ["timestamp"]].copy()
    normal["date"] = normal["timestamp"].dt.strftime("%Y-%m-%d").to_numpy()
    normal["false_alarm"] = predicted_attack[test["label"].eq(0).to_numpy()]
    by_day = []
    for day, group in normal.groupby("date", sort=True):
        alarms = int(group["false_alarm"].sum())
        by_day.append({
            "model": record["model"],
            "date": day,
            "normal_rows": len(group),
            "false_alarms": alarms,
            "false_alarm_rate": alarms / len(group),
        })

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    type_output = output.with_name("weather_test_attack_type_diagnostics.csv")
    day_output = output.with_name("weather_test_daily_false_alarms.csv")
    pd.DataFrame([record]).to_csv(output, index=False)
    pd.DataFrame(by_type).to_csv(type_output, index=False)
    pd.DataFrame(by_day).to_csv(day_output, index=False)

    print(json.dumps(record, indent=2, sort_keys=True))
    print("Training attack types:",
          train.loc[train["label"] == 1, "type"].value_counts().sort_index().to_dict())
    print("Test attack types:",
          test.loc[test["label"] == 1, "type"].value_counts().sort_index().to_dict())
    print("Metrics saved to {}".format(output))
    print("Attack-type report saved to {}".format(type_output))
    print("Daily false-alarm report saved to {}".format(day_output))
    print("Exploratory holdout: do not use these results to tune the model.")


if __name__ == "__main__":
    main()
