"""Build strictly past-only context features for Modbus records."""
import pandas as pd

from .preprocessing import FEATURE_COLUMNS

CONTEXT_COLUMNS = [
    "{}_past_value".format(feature)
    for feature in FEATURE_COLUMNS
] + [
    "{}_past_mean_5".format(feature)
    for feature in FEATURE_COLUMNS
] + [
    "{}_change_from_past".format(feature)
    for feature in FEATURE_COLUMNS
]


def add_past_context_features(frame):
    """Add prior-timestamp values and rolling means without using future rows.

    Rows sharing a timestamp get context from the previous distinct timestamp,
    not from other rows at their own timestamp.
    """
    timestamp_values = (
        frame.groupby("timestamp", sort=True)[FEATURE_COLUMNS]
        .mean()
        .reset_index()
    )
    history = timestamp_values[["timestamp"]].copy()

    for feature in FEATURE_COLUMNS:
        previous = timestamp_values[feature].shift(1)
        history["{}_past_value".format(feature)] = previous
        history["{}_past_mean_5".format(feature)] = (
            timestamp_values[feature].shift(1).rolling(5, min_periods=1).mean()
        )
        history["{}_change_from_past".format(feature)] = (
            timestamp_values[feature] - previous
        )

    rows = frame.copy()
    rows["_original_order"] = range(len(rows))
    rows = rows.merge(history, on="timestamp", how="left", validate="many_to_one", sort=False)
    return rows.sort_values("_original_order").drop(columns="_original_order").reset_index(drop=True)
