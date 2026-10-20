"""Evaluate a chronological TON_IoT Fridge sensor baseline."""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from apt_detection.physical_sensor.evaluate import evaluate_binary  # noqa: E402

NUMERIC_FEATURES = ["fridge_temperature"]
CATEGORICAL_FEATURES = ["temp_condition"]
FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES
REQUIRED_COLUMNS = ["date", "time", "label", "type", *FEATURE_COLUMNS]
DEFAULT_DATA = Path("data/raw/ton_iot/IoT_Fridge.csv")


def load_fridge_csv(path):
    """Load and validate the processed Fridge CSV without changing it."""
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
        raise ValueError("Missing or invalid date/time values found.")

    frame["fridge_temperature"] = pd.to_numeric(
        frame["fridge_temperature"], errors="coerce"
    )
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    frame["temp_condition"] = (
        frame["temp_condition"].astype(str).str.strip().str.lower()
    )
    checked = ["fridge_temperature", "label"]
    if frame[checked].isna().any().any() or frame["temp_condition"].eq("").any():
        raise ValueError("Missing or nonnumeric model values found.")
    frame["label"] = frame["label"].astype(int)
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("Expected binary label values 0 and 1.")
    return frame


def chronological_split(frame, cutoff_date):
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


def make_model():
    """Scale numeric temperature and one-hot encode the observed condition."""
    preprocessing = ColumnTransformer(
        transformers=[
            ("temperature", StandardScaler(), NUMERIC_FEATURES),
            ("condition", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )
    return make_pipeline(
        preprocessing,
        LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--cutoff", default="2019-04-26",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/fridge_model_comparison.csv"))
    args = parser.parse_args()

    frame = load_fridge_csv(args.data)
    train, test = chronological_split(frame, args.cutoff)
    model = make_model()
    model.fit(train[FEATURE_COLUMNS], train["label"])
    probability = model.predict_proba(test[FEATURE_COLUMNS])[:, 1]
    metrics = evaluate_binary(test["label"], probability)
    predicted_attack = probability >= 0.5

    record = {
        "model": "standardized_logistic_regression_one_hot_condition",
        "dataset": "TON_IoT_Fridge",
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

    attack_mask = test["label"].eq(1).to_numpy()
    attack_rows = test.loc[test["label"] == 1, "type"].astype(str).str.strip().reset_index(drop=True)
    attack_frame = pd.DataFrame({
        "type": attack_rows,
        "detected": predicted_attack[attack_mask],
    })
    by_type = []
    for attack_type, group in attack_frame.groupby("type", sort=True):
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
    normal["false_alarm"] = predicted_attack[~attack_mask]
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
    type_output = output.with_name("fridge_test_attack_type_diagnostics.csv")
    day_output = output.with_name("fridge_test_daily_false_alarms.csv")
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
