"""Training helpers for the device telemetry module."""
import numpy as np


def kind_weights(kind):
    """Weights giving normal 50%, flood 25% and other attacks 25% of total importance."""
    kind = np.asarray(kind)
    w = np.ones(len(kind), dtype=float)
    shares = {"normal": 0.50, "flood": 0.25, "other": 0.25}
    for k, share in shares.items():
        mask = kind == k
        if mask.any():
            w[mask] = share * len(kind) / mask.sum()
    return w


def cv_scores(make_model, X, y, kind, folds, weighted=True):
    """Out-of-fold attack scores: each row is scored by a model trained without its fold."""
    X, y, kind = np.asarray(X), np.asarray(y), np.asarray(kind)
    scores = np.zeros(len(y), dtype=float)
    for train_idx, test_idx in folds:
        model = make_model()
        w = kind_weights(kind[train_idx]) if weighted else None
        model.fit(X[train_idx], y[train_idx], sample_weight=w)
        scores[test_idx] = model.predict_proba(X[test_idx])[:, 1]
    return scores