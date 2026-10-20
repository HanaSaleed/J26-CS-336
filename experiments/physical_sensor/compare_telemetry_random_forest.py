"""Run a fixed Random Forest comparison across TON_IoT telemetry sensors."""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from apt_detection.physical_sensor.evaluate import evaluate_binary  # noqa: E402
from compare_telemetry_sensors import DATASETS, load_sensor_csv  # noqa: E402


def make_model(config):
    """Prepare numeric/categorical sensor fields and fit a fixed balanced forest."""
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
        RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw/ton_iot"))
    parser.add_argument("--cutoff", default="2019-04-26",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/ton_iot_sensor_random_forest_comparison.csv"))
    args = parser.parse_args()
    data_dir = args.data_dir if args.data_dir.is_absolute() else ROOT / args.data_dir
    cutoff = pd.Timestamp(args.cutoff).normalize()
    results, by_type, by_day = [], [], []

    for name, config in DATASETS.items():
        frame, excluded, features = load_sensor_csv(name, data_dir)
        is_train = frame["timestamp"].dt.normalize() <= cutoff
        train = frame.loc[is_train].copy()
        test = frame.loc[~is_train].copy()
        if train.empty or test.empty or set(train["label"]) != {0, 1} or set(test["label"]) != {0, 1}:
            raise ValueError("{} cutoff must leave both labels in train and test.".format(name))

        model = make_model(config)
        model.fit(train[features], train["label"])
        probability = model.predict_proba(test[features])[:, 1]
        predicted = probability >= 0.5
        record = {
            "sensor": name,
            "dataset": "TON_IoT_{}".format(name.title()),
            "model": "random_forest_balanced_subsample_100_trees",
            "split": "chronological_exploratory_holdout",
            "cutoff_inclusive": args.cutoff,
            "features": ";".join(features),
            "excluded_undated_rows": excluded,
            "train_rows": len(train),
            "test_rows": len(test),
            **evaluate_binary(test["label"], probability),
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

        print(json.dumps(record, sort_keys=True))
        del model, frame, train, test

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    type_output = output.with_name("ton_iot_sensor_random_forest_attack_types.csv")
    day_output = output.with_name("ton_iot_sensor_random_forest_daily_false_alarms.csv")
    pd.DataFrame(results).to_csv(output, index=False)
    pd.DataFrame(by_type).to_csv(type_output, index=False)
    pd.DataFrame(by_day).to_csv(day_output, index=False)
    print("Summary saved to {}".format(output))
    print("Attack-type report saved to {}".format(type_output))
    print("Daily false-alarm report saved to {}".format(day_output))
    print("Exploratory holdout: do not tune models on these test results.")


if __name__ == "__main__":
    main()
