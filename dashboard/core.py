"""Research dashboard inference contract: predictions never see ground truth.

Only load trusted local .joblib files you trained. ToN-IoT flow classification
is not an APT campaign verdict or a real-time IIoT window detector.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import joblib
import numpy as np
import pandas as pd

ALL_FEATURES = (
    "src_port", "dst_port", "proto", "service", "duration",
    "src_bytes", "dst_bytes", "conn_state", "src_pkts", "dst_pkts",
)
NUMERIC = {"src_port", "dst_port", "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts"}
WHOLE = {"src_port", "dst_port", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts"}
CATEGORY = {"proto", "service", "conn_state"}
LABEL_COLUMNS = {"label", "type", "attack_type", "ground_truth", "true_label"}


def read_registry(path: Path) -> list[dict]:
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if raw.get("schema_version") != 1 or not isinstance(raw.get("models"), list):
        raise ValueError("Invalid model registry")
    models = raw["models"]
    ids = [m["id"] for m in models]
    if len(ids) != len(set(ids)):
        raise ValueError("Repeated model id")
    for entry in models:
        features = entry["features"]
        if not features or len(features) != len(set(features)) or not set(features) <= set(ALL_FEATURES):
            raise ValueError("Invalid model feature schema")
        if entry.get("signal") != "network":
            raise ValueError("Only network flow model entries are supported in v2")
    return models


def root_path(root: Path, rel: str) -> Path:
    """Registry paths must stay inside the research root."""
    root = Path(root).resolve()
    path = (root / rel).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Registry path escapes project root")
    return path


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for data in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def read_report(root: Path, config: Mapping) -> dict:
    report_file = root_path(root, config["report_path"])
    if not report_file.is_file():
        raise FileNotFoundError(f"Missing report: {report_file}")
    report = json.loads(report_file.read_text(encoding="utf-8-sig"))
    if report.get("project_id") != "J26-CS-336":
        raise ValueError("Wrong research project report")
    report_features = report.get("input_feature_names", report.get("input_features"))
    if report_features != config["features"]:
        raise ValueError("Report input features do not match model registry")
    return report


def report_metrics(report: dict) -> dict:
    for key in ("decision_tree_validation", "ablation_validation", "validation_metrics"):
        if isinstance(report.get(key), dict):
            return report[key]
    raise ValueError("Saved report has no recognized validation metrics")


def normalize_input(raw: Mapping, features: list[str] | tuple[str, ...]) -> pd.DataFrame:
    """Construct prediction frame from exact model feature schema. NEVER copy labels."""
    missing = [f for f in features if f not in raw]
    if missing:
        raise ValueError("Missing required inputs: " + ", ".join(missing))
    frame = {}
    for feat in features:
        value = raw[feat]
        if feat in NUMERIC:
            if value is None or str(value).strip() == "":
                # Training numeric policy: median imputer handles blank numeric values.
                number = float("nan")
            else:
                try:
                    number = float(value)
                except (TypeError, ValueError, OverflowError) as ex:
                    raise ValueError(f"{feat}: invalid numeric input") from ex
                if not math.isfinite(number) or number < 0:
                    raise ValueError(f"{feat}: value must be finite and nonnegative")
                if feat in WHOLE and not number.is_integer():
                    raise ValueError(f"{feat}: expected a whole number")
                if feat in {"src_port", "dst_port"} and number > 65535:
                    raise ValueError(f"{feat}: port must be 0–65535")
            frame[feat] = number
        elif feat in CATEGORY:
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{feat}: expected a text category")
            frame[feat] = (value or "").strip() or "__MISSING__"
        else:
            raise ValueError(f"Unexpected feature name: {feat}")
    return pd.DataFrame([frame], columns=list(features))


def load_model(root: Path, config: Mapping):
    """Load only project-owned model. Check report and exact feature schema."""
    report = read_report(root, config)
    model_file = root_path(root, config["model_path"])
    if not model_file.is_file():
        raise FileNotFoundError(f"Missing saved model: {model_file}")
    # Pickle-based format. Never load artifacts from unknown persons/sources.
    pipe = joblib.load(model_file)
    if not hasattr(pipe, "named_steps") or not {"preprocessing", "classifier"} <= set(pipe.named_steps):
        raise ValueError("Model is not a fitted preprocess + classifier pipeline")
    transformer = pipe.named_steps["preprocessing"]
    clf = pipe.named_steps["classifier"]
    if list(clf.classes_) != [0, 1]:
        raise ValueError("Expected binary classes 0 normal / 1 attack")
    sample = {f: 0 if f in NUMERIC else "-" for f in config["features"]}
    probe = normalize_input(sample, config["features"])
    try:
        pipe.predict(probe)
    except Exception as ex:
        raise ValueError("Model cannot predict from registry input schema") from ex
    n = len(transformer.get_feature_names_out())
    if report.get("encoded_feature_count") != n:
        raise ValueError("Model encoded dimension does not match saved report")
    return pipe, report


def predict(pipe, config: Mapping, raw: Mapping, *, include_trace: bool = True) -> dict:
    frame = normalize_input(raw, config["features"])
    y = int(pipe.predict(frame)[0])
    clf = pipe.named_steps["classifier"]
    attack_index = list(clf.classes_).index(1)
    score = float(pipe.predict_proba(frame)[0, attack_index])
    if not (math.isfinite(score) and 0 <= score <= 1):
        raise ValueError("Invalid prediction score")
    result = {"predicted_label": y, "prediction_text": "ATTACK-LIKE CONNECTION" if y else "NORMAL-LIKE CONNECTION",
              "attack_score": score, "normal_score": 1 - score,
              "model_id": config["id"], "source": "manual", "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if include_trace:
        encoded = pipe.named_steps["preprocessing"].transform(frame)
        array = encoded.toarray() if hasattr(encoded, "toarray") else np.asarray(encoded)
        names = pipe.named_steps["preprocessing"].get_feature_names_out()
        result["encoded_features"] = int(array.shape[1])
        result["active_encoded_values"] = [
            {"feature": str(n), "value": float(v)} for n, v in zip(names, array[0])
            if float(v) != 0 and np.isfinite(v)
        ]
    # Ground truth isn't in the result and never enters prediction.
    return result


def load_validation(root: Path, config: Mapping, report: dict) -> pd.DataFrame:
    """Validation-only; NEVER uses test.csv. Validate SHA256 before looking at rows."""
    rel = config["validation_path"]
    if Path(rel).name != "validation.csv":
        raise ValueError("Validation replay must use validation.csv, never a test partition")
    path = root_path(root, rel)
    digest = report.get("source_sha256", {}).get("validation")
    if not digest or not path.is_file() or hash_file(path) != digest:
        raise ValueError("Validation CSV is missing or does not match the model's report SHA256")
    df = pd.read_csv(path, dtype="string", keep_default_na=False, encoding="utf-8")
    required = set(config["features"]) | {"label", "type"}
    if not required <= set(df.columns):
        raise ValueError("Validation data missing model inputs or ground truth")
    if not df["label"].isin(["0", "1"]).all():
        raise ValueError("Unrecognized ground truth label")
    expected = report.get("validation_records", report.get("validation_rows"))
    if expected is not None and int(expected) != len(df):
        raise ValueError("Validation row count differs from report")
    return df


def blind_validation_record(df: pd.DataFrame, index: int, features) -> dict:
    if index < 0 or index >= len(df):
        raise IndexError("Invalid validation record index")
    return {name: df.iloc[index][name] for name in features}


def ground_truth_record(df: pd.DataFrame, index: int) -> dict:
    if index < 0 or index >= len(df):
        raise IndexError("Invalid validation record index")
    return {"actual_label": int(df.iloc[index]["label"]), "dataset_type": str(df.iloc[index]["type"])}


def read_blind_batch(file, features, *, limit=500) -> pd.DataFrame:
    """Accept a label-free CSV; do not silently use or export labels."""
    df = pd.read_csv(file, dtype="string", keep_default_na=False, encoding="utf-8-sig", nrows=limit + 1)
    if len(df) > limit:
        raise ValueError(f"Maximum {limit} rows per batch demo")
    lowered = {str(c).lower().strip() for c in df.columns}
    if lowered & LABEL_COLUMNS:
        raise ValueError("Uploaded file includes label/type columns; create a feature-only CSV first")
    if set(df.columns) != set(features):
        raise ValueError(f"Expected exactly: {', '.join(features)}")
    if not len(df):
        raise ValueError("CSV has no data rows")
    cleaned = [normalize_input(record, features).iloc[0].to_dict() for record in df.to_dict("records")]
    return pd.DataFrame(cleaned, columns=list(features))


def batch_predict(pipe, config, frame: pd.DataFrame) -> pd.DataFrame:
    """Label-free batch prediction. No accuracy metrics without ground truth."""
    if list(frame.columns) != list(config["features"]):
        raise ValueError("Batch columns/order do not match active model")
    preds = pipe.predict(frame)
    attack_index = list(pipe.named_steps["classifier"].classes_).index(1)
    scores = pipe.predict_proba(frame)[:, attack_index]
    return pd.DataFrame({"row_number": range(1, len(frame) + 1),
                         "predicted_label": [int(x) for x in preds],
                         "predicted_class": ["Attack-like" if int(x) else "Normal-like" for x in preds],
                         "attack_score": np.round(scores, 6)})


def evidence_event(result: dict, *, source: str, signal="network", device_id=None) -> dict:
    """Integration-ready demonstration event. No ground-truth label or ATT&CK attribution."""
    return {"schema_version": "0.1", "project_id": "J26-CS-336", "timestamp_utc": result["timestamp_utc"],
            "signal": signal, "source": source, "device_id": device_id,
            "model_id": result["model_id"], "prediction": result["predicted_label"],
            "score": round(result["attack_score"], 6), "window_seconds": None,
            "notes": "ToN-IoT flow-level demo only; not live, not APT attribution", "evidence": []}
