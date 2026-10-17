"""Evaluation helpers for the device telemetry module."""
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, average_precision_score


def score_report(y, score, kind, threshold=0.5):
    """Metrics for one set of predictions.
    y: true labels (0/1); score: attack score per process (0..1);
    kind: 'normal' / 'flood' / 'other' per process."""
    y = np.asarray(y)
    score = np.asarray(score, dtype=float)
    kind = np.asarray(kind)
    pred = (score >= threshold).astype(int)
    other_or_normal = kind != "flood"
    return {
        "recall_all":   pred[y == 1].mean(),
        "recall_flood": pred[kind == "flood"].mean(),
        "recall_other": pred[kind == "other"].mean(),
        "fpr":          pred[kind == "normal"].mean(),
        "precision":    precision_score(y, pred, zero_division=0),
        "pr_auc_other": average_precision_score(y[other_or_normal], score[other_or_normal]),
    }