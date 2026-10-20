"""Rank fused sensor inputs using training rows only (no holdout scoring)."""
import argparse
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from compare_sensor_fusion import aggregate_sensor, make_model
from compare_telemetry_sensors import DATASETS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw/ton_iot"))
    parser.add_argument("--cutoff", default="2019-04-26",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/ton_iot_sensor_fusion_training_features.csv"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    data_dir = args.data_dir if args.data_dir.is_absolute() else root / args.data_dir

    per_sensor = {
        name: aggregate_sensor(name, config, data_dir)[0]
        for name, config in DATASETS.items()
    }
    feature_tables = [table.drop(columns="label") for table in per_sensor.values()]
    features = pd.concat(feature_tables, axis=1, join="inner").sort_index()
    label_tables = pd.concat(
        [table["label"].rename(name) for name, table in per_sensor.items()],
        axis=1,
        join="inner",
    ).sort_index()
    if label_tables.nunique(axis=1).gt(1).any():
        raise ValueError("Sensor labels disagree on shared timestamp seconds.")
    labels = label_tables.iloc[:, 0].astype(int)
    cutoff = pd.Timestamp(args.cutoff).normalize()
    train_mask = features.index.normalize() <= cutoff
    x_train = features.loc[train_mask]
    y_train = labels.loc[train_mask]
    if set(y_train) != {0, 1}:
        raise ValueError("The training period must contain both binary labels.")

    numeric, categorical = [], []
    for name, config in DATASETS.items():
        numeric.extend(name + "__" + field for field in config["numeric"])
        categorical.extend(name + "__" + field for field in config["categorical"])
    prep_config = {"numeric": numeric, "categorical": categorical}
    models = {
        "balanced_logistic_regression": LogisticRegression(
            class_weight="balanced", max_iter=2000, random_state=42
        ),
        "random_forest_balanced_subsample_100_trees": RandomForestClassifier(
            n_estimators=100, class_weight="balanced_subsample",
            random_state=42, n_jobs=-1,
        ),
    }
    detail_rows = []
    for model_name, classifier in models.items():
        model = make_model(prep_config, classifier)
        model.fit(x_train, y_train)
        transformed_names = model.steps[0][1].get_feature_names_out()
        fitted_classifier = model.steps[-1][1]
        if hasattr(fitted_classifier, "coef_"):
            scores = fitted_classifier.coef_[0]
            score_type = "signed_logistic_coefficient"
            rank_values = abs(scores)
        else:
            scores = fitted_classifier.feature_importances_
            score_type = "random_forest_impurity_importance"
            rank_values = scores

        for transformed_name, score, rank_value in zip(transformed_names, scores, rank_values):
            parts = transformed_name.split("__", 2)
            source_sensor = parts[1] if len(parts) > 1 else "unknown"
            detail_rows.append({
                "model": model_name,
                "source_sensor": source_sensor,
                "transformed_feature": transformed_name,
                "score_type": score_type,
                "score": float(score),
                "rank_value": float(rank_value),
            })

    details = pd.DataFrame(detail_rows)
    summary = details.groupby(["model", "source_sensor"], as_index=False).agg(
        transformed_features=("transformed_feature", "count"),
        total_rank_value=("rank_value", "sum"),
        mean_rank_value=("rank_value", "mean"),
    )
    summary["share_of_total_rank_value"] = summary["total_rank_value"] / summary.groupby("model")["total_rank_value"].transform("sum")
    details = details.sort_values(["model", "source_sensor", "rank_value"], ascending=[True, True, False])

    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    summary_output = output.with_name("ton_iot_sensor_fusion_training_sensor_summary.csv")
    details.to_csv(output, index=False)
    summary.to_csv(summary_output, index=False)
    print("Training rows: {} (normal={}, attack={})".format(
        len(y_train), int((y_train == 0).sum()), int((y_train == 1).sum())
    ))
    print("Feature ranking saved to {}".format(output))
    print("Per-sensor summary saved to {}".format(summary_output))
    print("This report fits on training data only and does not score the holdout.")


if __name__ == "__main__":
    main()
