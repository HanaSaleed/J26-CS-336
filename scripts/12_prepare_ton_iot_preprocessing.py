"""J26-CS-336 / Phase 5.17: fit ToN-IoT flow preprocessing on TRAIN ONLY.

Run from D:\\IIoT-APT-Research:
    .\\.venv\\Scripts\\python.exe .\\scripts\\12_prepare_ton_iot_preprocessing.py

Inputs: data/processed/ton_iot_group_holdout_v1/{train,validation}.csv
        data/processed/ton_iot_group_holdout_v1/split_manifest.json
Outputs (new, never overwritten):
        models/ton_iot_preprocessing_v1/preprocessor.joblib
        reports/ton_iot_preprocessing_v1.json

This script never reads test.csv, never modifies source partitions, and never
trains a classifier. Dataset has no usable event timestamp for 5/10/15/20s.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

NUMERIC = ("src_port", "dst_port", "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts")
CATEGORICAL = ("proto", "service", "conn_state")
FEATURES = ("src_port", "dst_port", "proto", "service", "duration", "src_bytes", "dst_bytes", "conn_state", "src_pkts", "dst_pkts")
LABELS = ("label", "type")
MISSING_CAT = "__MISSING__"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=Path("data/processed/ton_iot_group_holdout_v1"))
    parser.add_argument("--model-dir", type=Path, default=Path("models/ton_iot_preprocessing_v1"))
    parser.add_argument("--report", type=Path, default=Path("reports/ton_iot_preprocessing_v1.json"))
    args = parser.parse_args()

    train_path = args.input_dir / "train.csv"
    validation_path = args.input_dir / "validation.csv"
    test_path = args.input_dir / "test.csv"
    manifest_path = args.input_dir / "split_manifest.json"
    for path in (train_path, validation_path, test_path, manifest_path):
        if not path.is_file():
            raise FileNotFoundError(f"Expected split file missing: {path}")
    # Fail before doing any fitting if outputs already exist.
    artifact = args.model_dir / "preprocessor.joblib"
    if args.model_dir.exists() or args.report.exists():
        raise FileExistsError(
            "Output version already exists. Do not overwrite prior research results; "
            "choose new --model-dir and --report paths for an intentional new version."
        )

    try:
        import joblib
        import numpy as np
        import pandas as pd
        import sklearn
        from sklearn.compose import ColumnTransformer
        from sklearn.impute import SimpleImputer
        from sklearn.preprocessing import OneHotEncoder
    except ImportError as exc:
        raise RuntimeError(
            "Missing ML library. In your project's Python 3.12 venv install: "
            "python -m pip install numpy pandas scikit-learn joblib"
        ) from exc

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("version") != "ton_iot_group_holdout_v1":
        raise ValueError("Unexpected split version in manifest")
    if tuple(manifest.get("candidate_input_features", [])) != FEATURES:
        raise ValueError("Candidate feature order differs from original split manifest")

    # TRAIN and VALIDATION only: deliberately leave the TEST file unopened.
    frames = {}
    for part, path in (("train", train_path), ("validation", validation_path)):
        df = pd.read_csv(path, dtype="string", keep_default_na=False, encoding="utf-8")
        expected_columns = set(FEATURES + LABELS)
        if set(df.columns) != expected_columns:
            raise ValueError(f"Unexpected columns in {part}: {list(df.columns)}")
        expected_rows = int(manifest["partitions"][part]["rows"])
        if len(df) != expected_rows:
            raise ValueError(f"{part} row count differs from manifest: {len(df)} != {expected_rows}")
        if not df["label"].isin(["0", "1"]).all():
            raise ValueError(f"Unexpected binary label in {part}")
        for col in NUMERIC:
            converted = pd.to_numeric(df[col], errors="coerce").astype("float64")
            # Refuse non-finite values rather than inventing numbers. Blank/NA
            # values can be imputed using training-only medians if present.
            malformed = df[col].str.strip().ne("") & converted.isna()
            if bool(malformed.any()):
                raise ValueError(f"Non-numeric value in {part}.{col}")
            values = converted.to_numpy()
            if np.isinf(values).any():
                raise ValueError(f"Infinite value in {part}.{col}")
            df[col] = converted
        for col in CATEGORICAL:
            df[col] = df[col].str.strip().replace("", MISSING_CAT).astype(str)
        frames[part] = df

    tr = frames["train"]
    va = frames["validation"]
    if set(tr["label"]) != {"0", "1"} or set(va["label"]) != {"0", "1"}:
        raise ValueError("Train and validation should both contain both binary labels")

    transformer = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), list(NUMERIC)),
            ("categorical", OneHotEncoder(handle_unknown="ignore"), list(CATEGORICAL)),
        ],
        remainder="drop",
    )
    transformer.fit(tr.loc[:, list(FEATURES)])  # exclusively TRAIN
    n_features = len(transformer.get_feature_names_out())
    tr_x = transformer.transform(tr.loc[:, list(FEATURES)])
    va_x = transformer.transform(va.loc[:, list(FEATURES)])
    if tr_x.shape != (len(tr), n_features) or va_x.shape != (len(va), n_features):
        raise RuntimeError("Preprocessing changed the number/order of features across partitions")

    categories = transformer.named_transformers_["categorical"].categories_
    unseen = {}
    for col, known in zip(CATEGORICAL, categories):
        outside = ~va[col].isin(set(known))
        unseen[col] = {
            "validation_rows_with_unseen_category": int(outside.sum()),
            "distinct_unseen_categories": sorted(va.loc[outside, col].unique().tolist()),
            "training_distinct_categories": len(known),
        }
    # Prediction score / test metrics intentionally absent: nothing trained.
    report = {
        "project_id": "J26-CS-336",
        "phase": "5.17 / train-only flow preprocessing",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input_split_version": manifest["version"],
        "input_files_sha256": {"train": sha256(train_path), "validation": sha256(validation_path),
                               "split_manifest": sha256(manifest_path)},
        "test_partition": "FILE PRESENCE VERIFIED ONLY; test.csv was NOT opened or transformed",
        "preprocessing_fit_on": "train.csv exclusively",
        "features_in_order": list(FEATURES),
        "numeric_features": list(NUMERIC),
        "categorical_features": list(CATEGORICAL),
        "categorical_policy": "Training-only one-hot fit, ignore unseen validation/test categories; '-' is kept as an observed service category",
        "numeric_policy": "Training-only median imputer; no scaling for tree-based baseline",
        "label_and_type_as_predictors": False,
        "rows": {"train": len(tr), "validation": len(va)},
        "labels": {"train": dict(Counter(tr["label"])), "validation": dict(Counter(va["label"]))},
        "encoded_feature_count": n_features,
        "encoded_feature_names": transformer.get_feature_names_out().tolist(),
        "validation_unknown_categories": unseen,
        "sklearn_version": sklearn.__version__,
        "pandas_version": pd.__version__,
        "numpy_version": np.__version__,
        "known_limitations": [
            "Group-disjoint by bidirectional 5-tuple, not by attack session/campaign or IP pair.",
            "Identical selected input signatures still overlap across the split.",
            "ToN-IoT train_test_network.csv lacks event timestamps; this is NOT a 5/10/15/20-second ML experiment.",
            "Using IP/port-based grouping does not guarantee held-out deployment environments.",
            "No classifier trained and no held-out test evaluation performed.",
        ],
    }

    args.model_dir.mkdir(parents=True, exist_ok=False)
    joblib.dump(transformer, artifact)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    print("=== J26-CS-336 TRAIN-ONLY PREPROCESSING ===")
    print("Input:", args.input_dir.resolve())
    print("Fitted on: train.csv ONLY")
    print("Records: train=", f"{len(tr):,}", "validation=", f"{len(va):,}")
    print("Original selected features:", len(FEATURES), "(7 numeric, 3 categorical)")
    print("Encoded output features:", n_features)
    print("Encoded arrays: train=", tr_x.shape, "validation=", va_x.shape)
    print("Validation category values not seen during training:")
    for col, value in unseen.items():
        print(f"  {col}: {value['validation_rows_with_unseen_category']} rows; values={value['distinct_unseen_categories']}")
    print("Labels excluded from features: label, type")
    print("test.csv was NOT opened. No classifier was trained.")
    print("Saved preprocessor:", artifact)
    print("Saved reproducibility report:", args.report)
    print("NEXT: inspect report; then run Decision Tree baseline with train/validation only.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        sys.exit(1)
