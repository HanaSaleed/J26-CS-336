"""Train and report a chronological TON_IoT Modbus baseline."""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from apt_detection.physical_sensor.preprocessing import (  # noqa: E402
    FEATURE_COLUMNS,
    chronological_split,
    load_modbus_csv,
)
from apt_detection.physical_sensor.train import fit_baseline  # noqa: E402
from apt_detection.physical_sensor.predict import predict_attack_probability  # noqa: E402
from apt_detection.physical_sensor.evaluate import evaluate_binary  # noqa: E402

DEFAULT_DATA = Path("data/raw/ton_iot/IoT_Modbus.csv")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA,
                        help="Path to the unchanged processed IoT_Modbus.csv")
    parser.add_argument("--cutoff", default="2019-04-25",
                        help="Last training date, inclusive (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path,
                        help="Optional path for a one-row metrics CSV")
    args = parser.parse_args()

    frame = load_modbus_csv(args.data)
    train, test = chronological_split(frame, args.cutoff)
    model = fit_baseline(train, FEATURE_COLUMNS)
    probability = predict_attack_probability(model, test, FEATURE_COLUMNS)
    metrics = evaluate_binary(test["label"], probability)

    record = {
        "model": "standardized_logistic_regression",
        "split": "chronological",
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
    print(json.dumps(record, indent=2, sort_keys=True))
    print("Training attack types:",
          train.loc[train["label"] == 1, "type"].value_counts().sort_index().to_dict())
    print("Test attack types:",
          test.loc[test["label"] == 1, "type"].value_counts().sort_index().to_dict())

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame([record]).to_csv(args.output, index=False)
        print("Metrics saved to {}".format(args.output))


if __name__ == "__main__":
    main()
