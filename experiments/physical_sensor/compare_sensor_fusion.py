"""Compare single-sensor and fused TON-IoT telemetry on shared seconds."""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from apt_detection.physical_sensor.evaluate import evaluate_binary  # noqa: E402
from compare_telemetry_sensors import DATASETS, load_sensor_csv  # noqa: E402


def _aggregate_category(frame, column):
    """Choose the most common nonmissing category per second, with stable ties."""
    counts = (
        frame.loc[frame[column].notna(), ["timestamp", column]]
        .groupby(["timestamp", column], sort=False)
        .size()
        .rename("count")
        .reset_index()
    )
    if counts.empty:
        return pd.Series(dtype=object, name=column)
    counts = counts.sort_values(
        ["timestamp", "count", column],
        ascending=[True, False, True],
        kind="stable",
    )
    return counts.drop_duplicates("timestamp").set_index("timestamp")[column]


def aggregate_sensor(name, config, data_dir):
    """Reduce a sensor to one median/mode feature row per timestamp second."""
    frame, excluded, features = load_sensor_csv(name, data_dir)
    grouped = frame.groupby("timestamp", sort=True)
    conflicts = int(grouped["label"].nunique().gt(1).sum())
    if conflicts:
        raise ValueError("{} has {} timestamps with conflicting binary labels.".format(name, conflicts))

    aggregated = pd.DataFrame(index=grouped.size().index)
    aggregated["label"] = grouped["label"].first().astype(int)
    for column in config["numeric"]:
        aggregated[name + "__" + column] = grouped[column].median()
    for column in config["categorical"]:
        aggregated[name + "__" + column] = _aggregate_category(frame, column).reindex(aggregated.index)
    return aggregated, excluded, len(frame), len(aggregated)


def make_model(config, classifier):
    """Build train-only imputation/encoding with one fixed classifier."""
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
    return make_pipeline(preprocessing, classifier)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw/ton_iot"))
    parser.add_argument("--cutoff", default="2019-04-26",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/ton_iot_sensor_fusion_comparison.csv"))
    args = parser.parse_args()
    data_dir = args.data_dir if args.data_dir.is_absolute() else ROOT / args.data_dir
    cutoff = pd.Timestamp(args.cutoff).normalize()

    per_sensor = {}
    alignment = []
    for name, config in DATASETS.items():
        aggregated, excluded, dated_rows, unique_seconds = aggregate_sensor(name, config, data_dir)
        per_sensor[name] = aggregated
        alignment.append({
            "sensor": name,
            "dated_source_rows": dated_rows,
            "unique_seconds": unique_seconds,
            "repeated_rows_aggregated": dated_rows - unique_seconds,
            "excluded_known_undated_normal_rows": excluded,
        })

    feature_tables = {
        name: table.drop(columns=["label"])
        for name, table in per_sensor.items()
    }
    shared_features = pd.concat(list(feature_tables.values()), axis=1, join="inner").sort_index()
    label_tables = pd.concat(
        [table["label"].rename(name) for name, table in per_sensor.items()],
        axis=1,
        join="inner",
    ).sort_index()
    if shared_features.empty:
        raise ValueError("The sensors have no shared timestamp seconds.")
    if label_tables.nunique(axis=1).gt(1).any():
        raise ValueError("Sensor labels disagree on shared timestamp seconds.")
    labels = label_tables.iloc[:, 0].astype(int)

    train_mask = shared_features.index.normalize() <= cutoff
    test_mask = ~train_mask
    if (not train_mask.any() or not test_mask.any()
            or set(labels.loc[train_mask]) != {0, 1}
            or set(labels.loc[test_mask]) != {0, 1}):
        raise ValueError("The cutoff must leave both labels in train and test.")

    feature_sets = {
        name: list(feature_tables[name].columns)
        for name in DATASETS
    }
    feature_sets["all_sensors"] = list(shared_features.columns)
    classifiers = {
        "balanced_logistic_regression": lambda: LogisticRegression(
            class_weight="balanced", max_iter=2000, random_state=42
        ),
        "random_forest_balanced_subsample_100_trees": lambda: RandomForestClassifier(
            n_estimators=100, class_weight="balanced_subsample",
            random_state=42, n_jobs=-1,
        ),
    }

    results, by_day = [], []
    for sensor_name, columns in feature_sets.items():
        numeric_columns = []
        categorical_columns = []
        for name, config in DATASETS.items():
            selected = set(config["numeric"] + config["categorical"])
            if sensor_name != "all_sensors" and sensor_name != name:
                continue
            numeric_columns.extend(
                name + "__" + col for col in config["numeric"]
                if name + "__" + col in columns
            )
            categorical_columns.extend(
                name + "__" + col for col in config["categorical"]
                if name + "__" + col in columns
            )
        config = {"numeric": numeric_columns, "categorical": categorical_columns}
        x_train = shared_features.loc[train_mask, columns]
        x_test = shared_features.loc[test_mask, columns]
        y_train = labels.loc[train_mask]
        y_test = labels.loc[test_mask]
        for model_name, classifier_factory in classifiers.items():
            model = make_model(config, classifier_factory())
            model.fit(x_train, y_train)
            probability = model.predict_proba(x_test)[:, 1]
            prediction = probability >= 0.5
            metrics = evaluate_binary(y_test, probability)
            base = {
                "sensor_set": sensor_name,
                "model": model_name,
                "split": "chronological_exploratory_holdout",
                "cutoff_inclusive": args.cutoff,
                "features": ";".join(columns),
                "aggregation": "median_numeric_mode_categorical_per_second",
                "train_rows": int(train_mask.sum()),
                "train_normal": int((y_train == 0).sum()),
                "train_attack": int((y_train == 1).sum()),
                "test_rows": int(test_mask.sum()),
                "test_normal": int((y_test == 0).sum()),
                "test_attack": int((y_test == 1).sum()),
                "shared_timestamp_rows": len(shared_features),
                **metrics,
            }
            results.append(base)

            attack_mask = y_test.eq(1).to_numpy()
            normal_test = shared_features.index[test_mask & labels.eq(0).to_numpy()]
            normal_report = pd.DataFrame({
                "date": normal_test.strftime("%Y-%m-%d"),
                "false_alarm": prediction[~attack_mask],
            })
            for day, group in normal_report.groupby("date", sort=True):
                alarms = int(group["false_alarm"].sum())
                by_day.append({
                    "sensor_set": sensor_name,
                    "model": model_name,
                    "date": day,
                    "normal_rows": len(group),
                    "false_alarms": alarms,
                    "false_alarm_rate": alarms / len(group),
                })
            print("{} / {}: ROC AUC={:.3f}, balanced accuracy={:.3f}, recall={:.3f}".format(
                sensor_name, model_name, metrics["roc_auc"],
                metrics["balanced_accuracy"], metrics["recall"],
            ), flush=True)
            del model

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    day_output = output.with_name("ton_iot_sensor_fusion_daily_false_alarms.csv")
    alignment_output = output.with_name("ton_iot_sensor_fusion_alignment.csv")
    pd.DataFrame(results).to_csv(output, index=False)
    pd.DataFrame(by_day).to_csv(day_output, index=False)
    alignment.append({
        "sensor": "all_sensors_inner_join",
        "dated_source_rows": "",
        "unique_seconds": len(shared_features),
        "repeated_rows_aggregated": "",
        "excluded_known_undated_normal_rows": "",
    })
    pd.DataFrame(alignment).to_csv(alignment_output, index=False)
    print("\nSummary saved to {}".format(output))
    print("Daily false-alarm report saved to {}".format(day_output))
    print("Timestamp alignment saved to {}".format(alignment_output))
    print("Exploratory holdout only: these dates were previously inspected; do not tune on them.")


if __name__ == "__main__":
    main()
