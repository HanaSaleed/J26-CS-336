"""Baseline model helpers for the physical-sensor module."""
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


def make_baseline_model():
    """Return standardized logistic regression with balanced training weights."""
    return make_pipeline(
        StandardScaler(),
        LogisticRegression(
            class_weight="balanced",
            max_iter=2000,
            random_state=42,
        ),
    )


def fit_baseline(train_frame, feature_columns):
    model = make_baseline_model()
    model.fit(train_frame[feature_columns], train_frame["label"])
    return model
