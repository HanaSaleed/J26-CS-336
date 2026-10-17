"""Compare the Modbus logistic baseline with a random-forest candidate."""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from apt_detection.physical_sensor.evaluate import evaluate_binary  # noqa: E402
from apt_detection.physical_sensor.predict import predict_attack_probability  # noqa: E402
from apt_detection.physical_sensor.preprocessing import (  # noqa: E402
    FEATURE_COLUMNS,
    chronological_split,
    load_modbus_csv,
)
from apt_detection.physical_sensor.train import fit_baseline  # noqa: E402

DEFAULT_DATA = Path("data/raw/ton_iot/IoT_Modbus.csv")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--cutoff", default="2019-04-25")
    parser.add_argument("--output", type=Path,
                        default=Path("docs/results/modbus_model_comparison.csv"))
    args = parser.parse_args()

    frame = load_modbus_csv(args.data)
    train, test = chronological_split(frame, args.cutoff)

    models = {
        "standardized_logistic_regression": fit_baseline(train, FEATURE_COLUMNS),
        "random_forest_balanced_subsample": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        ).fit(train[FEATURE_COLUMNS], train["label"]),
    }

    records = []
    for name, model in models.items():
        probability = predict_attack_probability(model, test, FEATURE_COLUMNS)
        records.append({
            "model": name,
            "split": "chronological_exploratory_comparison",
            "cutoff_inclusive": args.cutoff,
            "features": ";".join(FEATURE_COLUMNS),
            "train_rows": len(train),
            "test_rows": len(test),
            **evaluate_binary(test["label"], probability),
        })

    output = args.output if args.output.is_absolute() else REPO_ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(records).to_csv(output, index=False)
    print(json.dumps(records, indent=2, sort_keys=True))
    print("Comparison saved to {}".format(output))
    print("Caution: this reuses the previously reported temporal holdout for model comparison;")
    print("treat the comparison as exploratory, not as an unbiased final model selection.")


if __name__ == "__main__":
    main()
