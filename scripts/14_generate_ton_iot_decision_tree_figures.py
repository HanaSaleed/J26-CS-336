"""J26-CS-336 | Create reproducible validation figures from an ALREADY trained Decision Tree.

Run from D:\\IIoT-APT-Research:
    .\\.venv\\Scripts\\python.exe .\\scripts\\14_generate_ton_iot_decision_tree_figures.py

Only reads existing validation.csv, saved model, and Decision Tree report.
NEVER reads test.csv, fits a model, changes input data, or overwrites output files.

Writes:
  reports/figures/ton_iot_decision_tree_v1/*.png (+ figure_manifest.json)
  reports/tables/ton_iot_decision_tree_v1/attack_type_performance.csv

Note: plot_tree is deliberately truncated to top 3 levels for readability.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

NUMERIC = ("src_port", "dst_port", "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts")
CATEGORICAL = ("proto", "service", "conn_state")
EXPECTED_FIGURES = (
    "confusion_matrix.png",
    "validation_metrics.png",
    "roc_curve.png",
    "precision_recall_curve.png",
    "feature_importance.png",
    "attack_type_recall.png",
    "decision_tree_overview.png",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_validation(path, feature_names, pd, np):
    """Match the dtype and missing-value policy from script 13 exactly."""
    df = pd.read_csv(path, dtype="string", keep_default_na=False, encoding="utf-8")
    if set(df.columns) != set(feature_names) | {"label", "type"}:
        raise ValueError(f"Unexpected validation CSV columns: {list(df.columns)}")
    if not df["label"].isin(["0", "1"]).all():
        raise ValueError("Validation file has invalid binary labels")
    for col in NUMERIC:
        numeric = pd.to_numeric(df[col], errors="coerce").astype("float64")
        invalid = df[col].str.strip().ne("") & numeric.isna()
        if bool(invalid.any()) or np.isinf(numeric.to_numpy()).any():
            raise ValueError(f"Invalid numeric validation column: {col}")
        df[col] = numeric
    for col in CATEGORICAL:
        df[col] = df[col].str.strip().replace("", "__MISSING__").astype(str)
    return df


def add_labels(ax, patches, fmt="{:.1%}", direction="horizontal"):
    for patch in patches:
        if direction == "horizontal":
            ax.annotate(fmt.format(patch.get_width()),
                        (patch.get_width(), patch.get_y() + patch.get_height() / 2),
                        xytext=(5, 0), textcoords="offset points", va="center", fontsize=9)
        else:
            ax.annotate(fmt.format(patch.get_height()),
                        (patch.get_x() + patch.get_width() / 2, patch.get_height()),
                        xytext=(0, 5), textcoords="offset points", ha="center", fontsize=9)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation", type=Path,
                        default=Path("data/processed/ton_iot_group_holdout_v1/validation.csv"))
    parser.add_argument("--report", type=Path, default=Path("reports/ton_iot_decision_tree_v1.json"))
    parser.add_argument("--model", type=Path,
                        default=Path("models/ton_iot_decision_tree_v1/decision_tree_pipeline.joblib"))
    parser.add_argument("--figures-dir", type=Path,
                        default=Path("reports/figures/ton_iot_decision_tree_v1"))
    parser.add_argument("--tables-dir", type=Path,
                        default=Path("reports/tables/ton_iot_decision_tree_v1"))
    args = parser.parse_args()

    for path in (args.validation, args.report, args.model):
        if not path.is_file():
            raise FileNotFoundError(f"Missing input file: {path}")
    if args.figures_dir.exists() or args.tables_dir.exists():
        raise FileExistsError("Figure/table output folder already exists. Outputs are never overwritten. ")
    if args.figures_dir == args.tables_dir:
        raise ValueError("Figure and table directories must be different")

    import joblib
    import matplotlib
    matplotlib.use("Agg")   # Works in PowerShell without opening graphic windows.
    import matplotlib.pyplot as plt
    import numpy as np
    import pandas as pd
    from sklearn import metrics
    from sklearn.tree import plot_tree

    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    if report.get("project_id") != "J26-CS-336":
        raise ValueError("Unexpected research project ID")
    if report.get("phase", "").split(" / ")[0] != "6.1":
        raise ValueError("Not a Decision Tree baseline report")
    if "NOT OPENED" not in report.get("test_partition", ""):
        raise ValueError("Report does not confirm held-out test partition remained unopened")
    if sha256(args.validation) != report["source_sha256"]["validation"]:
        raise ValueError("Validation CSV SHA256 does not match saved report; stopped")

    feature_names = report["input_feature_names"]
    if set(feature_names) != set(NUMERIC) | set(CATEGORICAL):
        raise ValueError("Unexpected input feature definition")
    df = read_validation(args.validation, feature_names, pd, np)
    if len(df) != int(report["validation_records"]):
        raise ValueError("Validation record count differs from report")
    y_true = df["label"].astype(int).to_numpy()
    if set(y_true) != {0, 1}:
        raise ValueError("Cannot create binary evaluation plots without both classes")

    # Only open a local joblib model that the user trained and trusts.
    pipeline = joblib.load(args.model)
    if list(pipeline.named_steps) != ["preprocessing", "classifier"]:
        raise ValueError("Unexpected model pipeline structure")
    transformer = pipeline.named_steps["preprocessing"]
    clf = pipeline.named_steps["classifier"]
    encoded_names = list(transformer.get_feature_names_out())
    if len(encoded_names) != int(report["encoded_feature_count"]):
        raise ValueError("Saved preprocessor doesn't match reported encoded features")
    if not hasattr(clf, "tree_"):
        raise ValueError("Saved classifier is not a fitted Decision Tree")

    X = df.loc[:, feature_names]
    y_pred = pipeline.predict(X)
    positive_index = list(clf.classes_).index(1)
    probabilities = pipeline.predict_proba(X)[:, positive_index]
    tn, fp, fn, tp = (int(v) for v in metrics.confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel())
    expected_cm = report["decision_tree_validation"]["confusion_matrix"]
    if {"TN": tn, "FP": fp, "FN": fn, "TP": tp} != expected_cm:
        raise ValueError("Validation predictions differ from the saved evaluation report")
    roc_auc = float(metrics.roc_auc_score(y_true, probabilities))
    ap = float(metrics.average_precision_score(y_true, probabilities))
    if not np.isclose(roc_auc, report["decision_tree_validation"]["roc_auc"], atol=1e-9):
        raise ValueError("ROC AUC mismatch with saved evaluation report")
    if not np.isclose(ap, report["decision_tree_validation"]["average_precision"], atol=1e-9):
        raise ValueError("Average precision mismatch with saved evaluation report")

    computed_by_type = {}
    for attack_type in sorted(df["type"].unique()):
        mask = (df["type"] == attack_type).to_numpy()
        total = int(mask.sum())
        predicted_attacks = int(np.sum(y_pred[mask] == 1))
        computed_by_type[attack_type] = (
            {"rows": total, "false_alerts": predicted_attacks} if attack_type == "normal"
            else {"rows": total, "attack_detected": predicted_attacks,
                  "attack_recall": predicted_attacks / total}
        )
        in_report = report["validation_detection_by_dataset_type"].get(attack_type)
        if not in_report or in_report["rows"] != total:
            raise ValueError(f"Attack-category mismatch in report: {attack_type}")
        count_key = "false_alerts" if attack_type == "normal" else "attack_detected"
        if in_report[count_key] != predicted_attacks:
            raise ValueError(f"Attack-category predictions mismatch in report: {attack_type}")

    # All checks complete before creating output folders.
    args.figures_dir.mkdir(parents=True, exist_ok=False)
    args.tables_dir.mkdir(parents=True, exist_ok=False)
    plt.rcParams.update({"font.size": 10, "axes.titlesize": 13, "figure.dpi": 110})

    def finish(fig, name):
        fig.savefig(args.figures_dir / name, dpi=190, bbox_inches="tight", facecolor="white")
        plt.close(fig)

    # 1: Confusion matrix
    fig, ax = plt.subplots(figsize=(7.5, 6.2))
    mat = np.array([[tn, fp], [fn, tp]])
    pic = ax.imshow(mat)
    fig.colorbar(pic, ax=ax, fraction=0.045, pad=0.04)
    ax.set_xticks([0, 1], ["Normal (0)", "Attack (1)"])
    ax.set_yticks([0, 1], ["Normal (0)", "Attack (1)"])
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True dataset label")
    ax.set_title("Decision Tree — Validation Confusion Matrix")
    for (i, j), count in np.ndenumerate(mat):
        ax.text(j, i, f"{count:,}", ha="center", va="center", fontsize=17,
                color="white" if count > mat.max() / 2 else "black")
    fig.text(.5, .01, "Validation only · Normal (0) / ToN-IoT attack (1)", ha="center", fontsize=9)
    finish(fig, "confusion_matrix.png")

    # 2: Model vs majority-class baseline metrics
    keys = ("accuracy", "balanced_accuracy", "attack_precision", "attack_recall", "attack_f1")
    labels = ("Accuracy", "Balanced accuracy", "Attack precision", "Attack recall", "Attack F1")
    dt = [float(report["decision_tree_validation"][k]) for k in keys]
    maj = [float(report["majority_class_baseline_validation"][k]) for k in keys]
    fig, ax = plt.subplots(figsize=(10, 6))
    y = np.arange(len(keys))
    bars1 = ax.barh(y - .18, dt, .34, label="Decision Tree")
    bars2 = ax.barh(y + .18, maj, .34, label="Always-predict-majority baseline")
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.14)
    ax.set_xlabel("Validation score (0–1)")
    ax.set_title("Decision Tree vs Majority Baseline — Validation")
    ax.legend(loc="center left", bbox_to_anchor=(1.02, 0.5))
    add_labels(ax, bars1)
    add_labels(ax, bars2)
    finish(fig, "validation_metrics.png")

    # 3: ROC
    fpr, tpr, _ = metrics.roc_curve(y_true, probabilities, pos_label=1)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(fpr, tpr, label=f"Decision Tree (ROC AUC={roc_auc:.4f})", linewidth=2)
    ax.plot([0, 1], [0, 1], linestyle="--", label="Random-ranking reference")
    ax.set(xlabel="False positive rate", ylabel="True positive rate (attack recall)",
           title="ROC Curve — Validation Only", xlim=(0, 1), ylim=(0, 1.02))
    ax.legend(loc="lower right")
    ax.grid(alpha=.2)
    finish(fig, "roc_curve.png")

    # 4: Precision-recall; always display attack prevalence baseline.
    precisions, recalls, _ = metrics.precision_recall_curve(y_true, probabilities, pos_label=1)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(recalls, precisions, linewidth=2, label=f"Decision Tree (AP={ap:.4f})")
    prevalence = float(np.mean(y_true))
    ax.axhline(prevalence, linestyle="--", label=f"Attack prevalence={prevalence:.3f}")
    ax.set(xlabel="Attack recall", ylabel="Attack precision",
           title="Precision–Recall Curve — Validation Only", xlim=(0, 1), ylim=(0, 1.02))
    ax.grid(alpha=.2)
    ax.legend(loc="lower left")
    finish(fig, "precision_recall_curve.png")

    # 5: Feature importance from fitted tree; not causal explanations.
    indices = np.argsort(clf.feature_importances_)[::-1]
    indices = [int(i) for i in indices if clf.feature_importances_[i] > 1e-12][:12]
    features = [encoded_names[i] for i in indices][::-1]
    importance = [float(clf.feature_importances_[i]) for i in indices][::-1]
    fig, ax = plt.subplots(figsize=(11.5, max(5, .55 * len(features) + 1.5)))
    ax.barh(features, importance)
    ax.set_xlabel("Gini importance (relative decrease in training impurity)")
    ax.set_title("Decision Tree — Top Split Features (NOT Causal)")
    ax.grid(axis="x", alpha=.2)
    fig.text(.5, .005, "High importance may reflect dataset-specific port/protocol shortcuts.", ha="center", fontsize=9)
    finish(fig, "feature_importance.png")

    # 6: Per-attack-category detection recall and actual number of misses.
    attack_items = [(typ, v) for typ, v in computed_by_type.items() if typ != "normal"]
    attack_items.sort(key=lambda item: item[1]["attack_recall"])
    attack_labels = [typ for typ, _ in attack_items]
    attack_recalls = [v["attack_recall"] for _, v in attack_items]
    fig, ax = plt.subplots(figsize=(10, max(5, .57 * len(attack_labels) + 1.5)))
    rects = ax.barh(attack_labels, attack_recalls)
    ax.set_xlim(0, 1.24)
    ax.set_xlabel("Proportion of category predicted as attack")
    ax.set_title("Attack Detection Recall by ToN-IoT Category — Validation")
    for bar, (typ, data) in zip(rects, attack_items):
        misses = data["rows"] - data["attack_detected"]
        ax.annotate(f"{data['attack_recall']:.1%}  ·  missed {misses}/{data['rows']}",
                    (bar.get_width(), bar.get_y() + bar.get_height()/2),
                    xytext=(5,0), textcoords="offset points", va="center", fontsize=9)
    ax.grid(axis="x", alpha=.2)
    finish(fig, "attack_type_recall.png")

    # 7: Truncated view of tree structure; figure is NOT entire trained tree.
    fig, ax = plt.subplots(figsize=(24, 10))
    plot_tree(clf, feature_names=encoded_names, class_names=["Normal", "Attack"],
              max_depth=3, rounded=True, fontsize=7, filled=False,
              impurity=True, proportion=False, ax=ax)
    ax.set_title("Decision Tree Structure — First 4 Levels Only (Depth 0–3)", fontsize=16)
    finish(fig, "decision_tree_overview.png")

    table_path = args.tables_dir / "attack_type_performance.csv"
    with table_path.open("x", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["dataset_type", "validation_records", "detected_attack", "missed_attack", "attack_recall", "false_alerts"])
        for typ, data in sorted(computed_by_type.items()):
            if typ == "normal":
                writer.writerow([typ, data["rows"], "", "", "", data["false_alerts"]])
            else:
                writer.writerow([typ, data["rows"], data["attack_detected"],
                                 data["rows"] - data["attack_detected"],
                                 f"{data['attack_recall']:.8f}", ""])

    manifest = {
        "project_id": "J26-CS-336",
        "model": "ToN-IoT Decision Tree flow-level baseline v1",
        "validation_only": True,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "validation_csv_sha256": sha256(args.validation),
        "model_sha256": sha256(args.model),
        "evaluation_report_sha256": sha256(args.report),
        "validation_records": len(df),
        "confusion_matrix": {"TN":tn, "FP":fp, "FN":fn, "TP":tp},
        "figures": list(EXPECTED_FIGURES),
        "table": str(table_path),
        "libraries": {"matplotlib": matplotlib.__version__},
        "interpretation_note": "Validation only. Generic network flow attack labels, not confirmed APT/window detection. First tree levels plotted; not full tree."
    }
    (args.figures_dir / "figure_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=== J26-CS-336 DECISION TREE VALIDATION FIGURES ===")
    print(f"Validation records: {len(df):,} | Confusion matrix verified against saved report")
    print("Test partition: NOT OPENED OR USED")
    print("Training: NONE; existing saved model reused")
    print("Figures:", args.figures_dir)
    for name in EXPECTED_FIGURES:
        print("  +", name)
    print("Tables:", table_path)
    print("Manifest:", args.figures_dir / "figure_manifest.json")
    print("SUCCESS: Seven PNG charts and one CSV evaluation table created.")
    print("NEXT: inspect charts, then conduct shortcut-feature checks before model comparisons.")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, FileExistsError, OSError, ValueError, KeyError, TypeError,
            ImportError, RuntimeError, AttributeError) as exc:
        print("STOPPED:", exc, file=sys.stderr)
        sys.exit(1)
