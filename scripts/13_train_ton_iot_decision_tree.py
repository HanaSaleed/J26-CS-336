"""J26-CS-336 | Train a SINGLE ToN-IoT binary Decision Tree flow-level baseline.

From D:\\IIoT-APT-Research:
    .\\.venv\\Scripts\\python.exe .\\scripts\\13_train_ton_iot_decision_tree.py

READS: train.csv, validation.csv, split_manifest.json, existing fitted
       preprocessor.joblib and preprocessing report.  test.csv is NOT opened.
WRITES: a new versioned model artifact and a JSON training/evaluation report.

IMPORTANT: This is a generic ToN-IoT attack/normal FLOW-level baseline,
NOT evidence for APT attribution or 5/10/15/20-second window detection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

FEATURES = (
    "src_port", "dst_port", "proto", "service", "duration",
    "src_bytes", "dst_bytes", "conn_state", "src_pkts", "dst_pkts",
)
NUMERIC = ("src_port", "dst_port", "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts")
CATEGORICAL = ("proto", "service", "conn_state")
MISSING_CAT = "__MISSING__"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_frame(path, expected_rows, pd, np):
    # Do not trust implicit dtype inference: preparation must match script 12.
    df = pd.read_csv(path, dtype="string", keep_default_na=False, encoding="utf-8")
    if set(df.columns) != set(FEATURES) | {"label", "type"}:
        raise ValueError(f"Unexpected columns in {path}: {list(df.columns)}")
    if len(df) != expected_rows:
        raise ValueError(f"Record count mismatch in {path}: {len(df)} != {expected_rows}")
    if not df["label"].isin(["0", "1"]).all():
        raise ValueError(f"Unexpected binary label in {path}")
    for col in NUMERIC:
        converted = pd.to_numeric(df[col], errors="coerce").astype("float64")
        malformed = df[col].str.strip().ne("") & converted.isna()
        if bool(malformed.any()) or np.isinf(converted.to_numpy()).any():
            raise ValueError(f"Invalid numeric values in {path}: {col}")
        df[col] = converted
    for col in CATEGORICAL:
        df[col] = df[col].str.strip().replace("", MISSING_CAT).astype(str)
    return df


def scores(y, pred, probabilities, skm, np):
    # Labels in confusion_matrix explicitly use [0,1].
    tn, fp, fn, tp = (int(x) for x in skm.confusion_matrix(y, pred, labels=[0, 1]).ravel())
    metrics = {
        "accuracy": float(skm.accuracy_score(y, pred)),
        "balanced_accuracy": float(skm.balanced_accuracy_score(y, pred)),
        "attack_precision": float(skm.precision_score(y, pred, pos_label=1, zero_division=0)),
        "attack_recall": float(skm.recall_score(y, pred, pos_label=1, zero_division=0)),
        "attack_f1": float(skm.f1_score(y, pred, pos_label=1, zero_division=0)),
        "normal_recall_specificity": float(tn / (tn + fp)) if tn + fp else None,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "confusion_matrix": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
        "roc_auc": None,
        "average_precision": None,
    }
    if probabilities is not None and len(np.unique(y)) == 2:
        metrics["roc_auc"] = float(skm.roc_auc_score(y, probabilities))
        metrics["average_precision"] = float(skm.average_precision_score(y, probabilities))
    return metrics


def _raise_json_type(obj):
    raise TypeError(f"Unsupported JSON result type: {type(obj).__name__}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=Path("data/processed/ton_iot_group_holdout_v1"))
    parser.add_argument("--preprocessor", type=Path, default=Path("models/ton_iot_preprocessing_v1/preprocessor.joblib"))
    parser.add_argument("--preprocessing-report", type=Path, default=Path("reports/ton_iot_preprocessing_v1.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("models/ton_iot_decision_tree_v1"))
    parser.add_argument("--report", type=Path, default=Path("reports/ton_iot_decision_tree_v1.json"))
    args = parser.parse_args()

    train_path = args.input_dir / "train.csv"
    val_path = args.input_dir / "validation.csv"
    manifest_path = args.input_dir / "split_manifest.json"
    for p in (train_path, val_path, manifest_path, args.preprocessor, args.preprocessing_report):
        if not p.is_file():
            raise FileNotFoundError(f"Missing required input: {p}")
    if args.output_dir.exists() or args.report.exists():
        raise FileExistsError("An output version already exists; choose a new --output-dir and --report. No overwriting.")

    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn import metrics as skm
    from sklearn.dummy import DummyClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.tree import DecisionTreeClassifier

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    prep_report = json.loads(args.preprocessing_report.read_text(encoding="utf-8"))
    if manifest.get("version") != "ton_iot_group_holdout_v1":
        raise ValueError("Unexpected input split version")
    if tuple(manifest.get("candidate_input_features", [])) != FEATURES:
        raise ValueError("Split manifest candidate features mismatch")
    if prep_report.get("preprocessing_fit_on") != "train.csv exclusively":
        raise ValueError("Training-only preprocessing not verified")
    if tuple(prep_report.get("features_in_order", [])) != FEATURES:
        raise ValueError("Feature order mismatch between split and preprocessor report")
    if prep_report.get("label_and_type_as_predictors") is not False:
        raise ValueError("Labels/type must not be model features")
    expected_hashes = prep_report["input_files_sha256"]
    for name, path in (("train", train_path), ("validation", val_path), ("split_manifest", manifest_path)):
        actual_hash = sha256(path)
        if actual_hash != expected_hashes.get(name):
            raise ValueError(f"Input changed since preprocessing: {name}; STOP to avoid mismatch")

    # Never read or transform held-out test.csv.
    train = read_frame(train_path, int(manifest["partitions"]["train"]["rows"]), pd, np)
    val = read_frame(val_path, int(manifest["partitions"]["validation"]["rows"]), pd, np)
    y_train = train["label"].astype(int).to_numpy()
    y_val = val["label"].astype(int).to_numpy()
    if set(y_train) != {0, 1} or set(y_val) != {0, 1}:
        raise ValueError("Train and validation must each contain normal and attack records")

    # Trusted LOCAL project artifact from Step 5.17. Only load joblib files you created/trust.
    transformer = joblib.load(args.preprocessor)
    names = transformer.get_feature_names_out().tolist()
    if names != prep_report.get("encoded_feature_names"):
        raise ValueError("Preprocessor categories or feature ordering changed")
    X_train = transformer.transform(train.loc[:, list(FEATURES)])
    X_val = transformer.transform(val.loc[:, list(FEATURES)])
    if X_train.shape != (len(train), len(names)) or X_val.shape != (len(val), len(names)):
        raise ValueError("Unexpected transformed feature dimensions")
    if not np.isfinite(X_train.toarray() if hasattr(X_train, "toarray") else X_train).all():
        raise ValueError("Nonfinite training features after transformation")
    if not np.isfinite(X_val.toarray() if hasattr(X_val, "toarray") else X_val).all():
        raise ValueError("Nonfinite validation features after transformation")

    # One fixed configuration: no hyperparameter search or repeated test peeking.
    settings = {"max_depth": 10, "min_samples_leaf": 20, "class_weight": "balanced", "random_state": 42}
    model = DecisionTreeClassifier(**settings)
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    train_duration = time.perf_counter() - t0

    t1 = time.perf_counter()
    predictions = model.predict(X_val)
    predict_seconds = time.perf_counter() - t1
    positive_index = list(model.classes_).index(1)
    probabilities = model.predict_proba(X_val)[:, positive_index]
    dt_metrics = scores(y_val, predictions, probabilities, skm, np)

    majority = DummyClassifier(strategy="most_frequent")
    majority.fit(X_train, y_train)
    maj_pred = majority.predict(X_val)
    maj_prob = majority.predict_proba(X_val)[:, list(majority.classes_).index(1)]
    majority_metrics = scores(y_val, maj_pred, maj_prob, skm, np)

    by_attack_type = {}
    for typ in sorted(val["type"].unique()):
        mask = (val["type"] == typ).to_numpy()
        if typ == "normal":
            by_attack_type[typ] = {"rows": int(mask.sum()), "false_alerts": int(np.sum(predictions[mask] == 1))}
        else:
            n = int(mask.sum())
            by_attack_type[typ] = {
                "rows": n,
                "attack_detected": int(np.sum(predictions[mask] == 1)),
                "attack_recall": float(np.mean(predictions[mask] == 1)) if n else None,
            }

    top_indices = np.argsort(model.feature_importances_)[::-1][:10]
    ranked = [{"feature": names[i], "importance": float(model.feature_importances_[i])}
              for i in top_indices if model.feature_importances_[i] > 0]

    # Pipeline includes already-fitted transformer; don't refit it on validation.
    deployment_pipeline = Pipeline([("preprocessing", transformer), ("classifier", model)])
    report = {
        "project_id": "J26-CS-336",
        "phase": "6.1 / ToN-IoT flow-level Decision Tree initial baseline",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "problem": "binary normal (0) vs ToN-IoT attack (1), not verified APT attribution",
        "split": "fixed-seed bidirectional-5-tuple-group-disjoint v1; not session/campaign-disjoint",
        "source_sha256": {"train": sha256(train_path), "validation": sha256(val_path),
                          "split_manifest": sha256(manifest_path),
                          "preprocessor_joblib": sha256(args.preprocessor)},
        "test_partition": "NOT OPENED, TRANSFORMED, OR EVALUATED",
        "training_records": len(train),
        "validation_records": len(val),
        "training_labels": dict(Counter(train["label"])),
        "validation_labels": dict(Counter(val["label"])),
        "input_feature_names": list(FEATURES),
        "encoded_feature_count": len(names),
        "decision_tree_hyperparameters": settings,
        "decision_tree_validation": dt_metrics,
        "majority_class_baseline_validation": majority_metrics,
        "validation_detection_by_dataset_type": by_attack_type,
        "training_seconds": train_duration,
        "validation_predict_seconds_batch": predict_seconds,
        "validation_predict_microseconds_per_row_batch_average": predict_seconds / len(val) * 1e6,
        "tree_depth": model.get_depth(),
        "tree_leaf_count": model.get_n_leaves(),
        "tree_node_count": model.tree_.node_count,
        "top_features_gini_importance_not_causal": ranked,
        "libraries": {"python_sklearn": sklearn.__version__, "numpy": np.__version__,
                      "pandas": pd.__version__, "joblib": joblib.__version__},
        "limitations": [
            "Validation-only baseline. No final held-out test evaluation performed.",
            "Distinct 5-tuples can share exact input signatures, host pairs or attack campaigns.",
            "ToN-IoT network file has no timestamps; results are not 5/10/15/20s window detection.",
            "Dataset generic attack labels are not proof of APT or MITRE technique identification.",
            "Batch mean time per row on Windows PC is NOT Raspberry Pi latency, memory or throughput.",
            "Impurity-based feature importances are descriptions of splits, not causal explanation.",
            "A fixed threshold of 0.5 is used; class-weight balancing may shift precision/recall.",
        ],
    }

    args.output_dir.mkdir(parents=True, exist_ok=False)
    model_path = args.output_dir / "decision_tree_pipeline.joblib"
    joblib.dump(deployment_pipeline, model_path)
    report["saved_model_bytes"] = model_path.stat().st_size
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False, allow_nan=False,
                  default=lambda obj: obj.item() if isinstance(obj, np.generic)
                  else _raise_json_type(obj))

    print("=== J26-CS-336 DECISION TREE FLOW BASELINE (TRAIN + VALIDATION ONLY) ===")
    print(f"Train: {len(train):,} | Validation: {len(val):,} | Encoded features: {len(names)}")
    print("Test: NOT OPENED or EVALUATED")
    print("Fixed settings:", settings)
    print(f"Tree: depth={model.get_depth()} leaves={model.get_n_leaves()} nodes={model.tree_.node_count}")
    for k in ("accuracy", "balanced_accuracy", "attack_precision", "attack_recall", "attack_f1", "false_positive_rate", "roc_auc", "average_precision"):
        print(f"  {k:20s} DT={dt_metrics[k]:.4f}  majority={majority_metrics[k]:.4f}")
    print("Confusion matrix (TN, FP, FN, TP):", dt_metrics["confusion_matrix"])
    print(f"Training seconds: {train_duration:.3f} | Batch validation prediction seconds: {predict_seconds:.3f}")
    print("Most influential training split features (Gini importance; NOT causal):")
    for entry in ranked[:7]:
        print(f"  {entry['feature']}: {entry['importance']:.4f}")
    print("Saved model:", model_path)
    print("Saved report:", args.report)
    print("NEXT: inspect class-specific errors and possible shortcut features before model comparison.")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, FileExistsError, OSError, ValueError, KeyError, RuntimeError, ImportError) as exc:
        print("STOPPED:", exc, file=sys.stderr)
        sys.exit(1)
