"""Loading and leakage-aware splitting for TON_IoT Modbus data."""
from pathlib import Path

import pandas as pd

FEATURE_COLUMNS = [
    "FC1_Read_Input_Register",
    "FC2_Read_Discrete_Value",
    "FC3_Read_Holding_Register",
    "FC4_Read_Coil",
]
REQUIRED_COLUMNS = ["date", "time", "label", "type", *FEATURE_COLUMNS]


def load_modbus_csv(path):
    """Load the processed CSV and validate fields used by the experiment."""
    frame = pd.read_csv(Path(path))
    missing_columns = sorted(set(REQUIRED_COLUMNS) - set(frame.columns))
    if missing_columns:
        raise ValueError("Missing required columns: {}".format(missing_columns))

    date = frame["date"].astype(str).str.strip()
    clock = frame["time"].astype(str).str.strip()
    frame["timestamp"] = pd.to_datetime(
        date + " " + clock,
        format="%d-%b-%y %H:%M:%S",
        errors="coerce",
    )
    if frame["timestamp"].isna().any():
        raise ValueError("Some date/time values could not be parsed.")

    for column in FEATURE_COLUMNS + ["label"]:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")
    checked = FEATURE_COLUMNS + ["label"]
    if frame[checked].isna().any().any():
        raise ValueError("Missing or nonnumeric values found in model fields.")
    frame["label"] = frame["label"].astype(int)
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("Expected binary label values 0 and 1.")
    return frame


def chronological_split(frame, cutoff_date):
    """Train through cutoff_date and test on all later calendar dates."""
    cutoff = pd.Timestamp(cutoff_date).normalize()
    day = frame["timestamp"].dt.normalize()
    train = frame.loc[day <= cutoff].copy()
    test = frame.loc[day > cutoff].copy()
    if train.empty or test.empty:
        raise ValueError("The cutoff produced an empty train or test partition.")
    if set(train["label"]) != {0, 1} or set(test["label"]) != {0, 1}:
        raise ValueError("Both labels must occur in both partitions.")
    return train, test
