"""Run comparable chronological logistic baselines across TON_IoT telemetry sensors."""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from apt_detection.physical_sensor.evaluate import evaluate_binary  # noqa: E402

DATASETS = {
    "weather": {
        "file": "IoT_Weather.csv",
        "numeric": ["temperature", "pressure", "humidity"],
        "categorical": [],
    },
    "thermostat": {
        "file": "IoT_Thermostat.csv",
        "numeric": ["current_temperature", "thermostat_status"],
        "categorical": [],
    },
    "fridge": {
        "file": "IoT_Fridge.csv",
        "numeric": ["fridge_temperature"],
        "categorical": ["temp_condition"],
    },
    "gps_tracker": {
        "file": "IoT_GPS_Tracker.csv",
        "numeric": ["latitude", "longitude"],
        "categorical": [],
    },
    "garage_door": {
        "file": "IoT_Garage_Door.csv",
        "numeric": [],
        "categorical": ["door_state", "sphone_signal"],
    },
    "motion_light": {
        "file": "IoT_Motion_Light.csv",
        "numeric": ["motion_status"],
        "categorical": ["light_status"],
    },
}


def load_sensor_csv(name, data_dir):
    """Load one sensor CSV and retain only rows usable in a time-based split."""
    config = DATASETS[name]
    features = config["numeric"] + config["categorical"]
    path = data_dir / config["file"]
    frame = pd.read_csv(path, low_memory=False)
    required = {"date", "time", "label", "type", *features}
    missing_columns = sorted(required - set(frame.columns))
    if missing_columns:
        raise ValueError("{} is missing columns {}".format(name, missing_columns))

    frame["type"] = frame["type"].astype("string").str.strip().str.lower()
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    if frame["label"].isna().any():
        raise ValueError("{} has missing or invalid labels.".format(name))
    frame["label"] = frame["label"].astype(int)
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("{} does not contain both binary labels.".format(name))

    for column in config["numeric"]:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")
    for column in config["categorical"]:
        values = frame[column].astype("string").str.strip().str.lower()
        frame[column] = values.astype(object).where(values.notna(), np.nan)

    if name == "garage_door":
        signal = frame["sphone_signal"]
        signal_map = {
            "false": "false", "0": "false", "0.0": "false",
            "true": "true", "1": "true", "1.0": "true",
        }
        normalized = signal.map(signal_map)
        unexpected = signal.notna() & normalized.isna()
        if unexpected.any():
            raise ValueError("Garage Door has unexpected sphone_signal values.")
        frame["sphone_signal"] = normalized.astype(object).where(normalized.notna(), np.nan)

    date = frame["date"].fillna("").astype(str).str.strip()
    clock = frame["time"].fillna("").astype(str).str.strip()
    blank_time = date.eq("") | clock.eq("")
    timestamp = pd.to_datetime(
        date + " " + clock,
        format="%d-%b-%y %H:%M:%S",
        errors="coerce",
    )
    if (timestamp.isna() & ~blank_time).any():
        raise ValueError("{} has nonblank but unparseable timestamps.".format(name))

    undated = blank_time | timestamp.isna()
    if undated.any():
        undated_rows = frame.loc[undated]
        known_undated = (
            undated_rows["label"].eq(0)
            & undated_rows["type"].eq("normal")
        )
        if name == "thermostat":
            known_undated &= undated_rows[config["numeric"]].eq(0).all(axis=1)
        elif name == "garage_door":
            known_undated &= undated_rows[config["categorical"]].isna().all(axis=1)
        else:
            raise ValueError("{} has undated rows that require review.".format(name))
        if not known_undated.all():
            raise ValueError("{} undated rows differ from the inspected normal rows.".format(name))

    excluded = int(undated.sum())
    frame = frame.loc[~undated].copy()
    frame["timestamp"] = timestamp.loc[~undated]
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("{} loses a label after excluding undated rows.".format(name))
    return frame, excluded, features


def make_model(config):
    """Scale numeric features, impute and encode categories, and fit balanced logistic regression."""
    transformers = []
    if config["numeric"]:
        numeric = make_pipeline(SimpleImputer(strategy="median"), StandardScaler())
        transformers.append(("numeric", numeric, config["numeric"]))
    if config["categorical"]:
        categorical = make_pipeline(
            SimpleImputer(strategy="most_frequent"),
            OneHotEncoder(handle_unknown="ignore"),
        )
        transformers.append(("categorical", categorical, config["categorical"]))
    preprocessing = ColumnTransformer(transformers=transformers)
    return make_pipeline(
        preprocessing,
        LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw/ton_iot"))
    parser.add_argument("--cutoff", default="2019-04-26",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/ton_iot_sensor_model_comparison.csv"))
    args = parser.parse_args()
    data_dir = args.data_dir if args.data_dir.is_absolute() else ROOT / args.data_dir

    results, by_type, by_day = [], [], []
    cutoff = pd.Timestamp(args.cutoff).normalize()
    for name, config in DATASETS.items():
        frame, excluded, features = load_sensor_csv(name, data_dir)
        is_train = frame["timestamp"].dt.normalize() <= cutoff
        train = frame.loc[is_train].copy()
        test = frame.loc[~is_train].copy()
        if train.empty or test.empty or set(train["label"]) != {0, 1} or set(test["label"]) != {0, 1}:
            raise ValueError("{} cutoff must leave both labels in train and test.".format(name))

        missing_train = int(train[features].isna().any(axis=1).sum())
        missing_test = int(test[features].isna().any(axis=1).sum())
        model = make_model(config)
        model.fit(train[features], train["label"])
        probability = model.predict_proba(test[features])[:, 1]
        predicted = probability >= 0.5
        metrics = evaluate_binary(test["label"], probability)
        record = {
            "sensor": name,
            "dataset": "TON_IoT_{}".format(name.title()),
            "model": "balanced_logistic_regression",
            "split": "chronological_exploratory_holdout",
            "cutoff_inclusive": args.cutoff,
            "features": ";".join(features),
            "excluded_undated_rows": excluded,
            "train_rows": len(train),
            "train_normal": int((train["label"] == 0).sum()),
            "train_attack": int((train["label"] == 1).sum()),
            "train_rows_with_missing_features": missing_train,
            "test_rows": len(test),
            "test_normal": int((test["label"] == 0).sum()),
            "test_attack": int((test["label"] == 1).sum()),
            "test_rows_with_missing_features": missing_test,
            **metrics,
        }
        results.append(record)

        attack_mask = test["label"].eq(1).to_numpy()
        attack_report = pd.DataFrame({
            "type": test.loc[test["label"] == 1, "type"].reset_index(drop=True),
            "detected": predicted[attack_mask],
        })
        for attack_type, group in attack_report.groupby("type", sort=True):
            detected = int(group["detected"].sum())
            by_type.append({
                "sensor": name,
                "attack_type": attack_type,
                "attack_rows": len(group),
                "detected": detected,
                "missed": len(group) - detected,
                "recall": detected / len(group),
            })

        normal = test.loc[test["label"] == 0, ["timestamp"]].copy()
        normal["date"] = normal["timestamp"].dt.strftime("%Y-%m-%d").to_numpy()
        normal["false_alarm"] = predicted[~attack_mask]
        for day, group in normal.groupby("date", sort=True):
            alarms = int(group["false_alarm"].sum())
            by_day.append({
                "sensor": name,
                "date": day,
                "normal_rows": len(group),
                "false_alarms": alarms,
                "false_alarm_rate": alarms / len(group),
            })

        print("{} train attack types: {}".format(
            name, train.loc[train["label"] == 1, "type"].value_counts().sort_index().to_dict()))
        print("{} test attack types: {}".format(
            name, test.loc[test["label"] == 1, "type"].value_counts().sort_index().to_dict()))
        del model, frame, train, test

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    type_output = output.with_name("ton_iot_sensor_test_attack_type_diagnostics.csv")
    day_output = output.with_name("ton_iot_sensor_test_daily_false_alarms.csv")
    pd.DataFrame(results).to_csv(output, index=False)
    pd.DataFrame(by_type).to_csv(type_output, index=False)
    pd.DataFrame(by_day).to_csv(day_output, index=False)
    print("\nSummary saved to {}".format(output))
    print("Attack-type report saved to {}".format(type_output))
    print("Daily false-alarm report saved to {}".format(day_output))
    print("Exploratory holdout: do not tune models on these test results.")


if __name__ == "__main__":
    main()
