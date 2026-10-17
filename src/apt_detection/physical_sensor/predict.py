"""Prediction helpers for physical-sensor models."""
import numpy as np


def predict_attack_probability(model, frame, feature_columns):
    """Return attack probabilities without using labels or attack-type metadata."""
    return np.asarray(model.predict_proba(frame[feature_columns])[:, 1], dtype=float)
