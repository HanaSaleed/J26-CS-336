"""Training helpers for the device telemetry module."""
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold


def _fit_and_score(make, model_type, X_tr, y_tr, kind_tr, X_te, normal_quantile=0.99):
    """Train one base model and score X_te. Supervised -> attack probability.
    Anomaly -> shifted anomaly score (cut-off at 0.5), trained on normal rows only."""
    model = make()
    if model_type == "supervised":
        model.fit(X_tr, y_tr)
        return model.predict_proba(X_te)[:, 1]
    normal = X_tr[kind_tr == "normal"]
    model.fit(normal)
    cutoff = np.quantile(-model.score_samples(normal), normal_quantile)
    return -model.score_samples(X_te) - cutoff + 0.5


def cv_stacked_scores(base, X, y, kind, groups, folds, inner_splits=4, seed=42):
    """Out-of-fold scores from a stacked ensemble, using nested cross-validation.
    base: dict of name -> (make_model, "supervised" or "anomaly")."""
    X, y, kind, groups = (np.asarray(a) for a in (X, y, kind, groups))
    out = np.zeros(len(y), dtype=float)
    for tr, te in folds:
        # inner round: base-model scores for the outer training rows, each from a model that never saw it
        inner = StratifiedGroupKFold(n_splits=inner_splits, shuffle=True, random_state=seed)
        meta_tr = np.zeros((len(tr), len(base)))
        for i_tr, i_te in inner.split(X[tr], kind[tr], groups[tr]):
            a, b = tr[i_tr], tr[i_te]
            for j, (make, mtype) in enumerate(base.values()):
                meta_tr[i_te, j] = _fit_and_score(make, mtype, X[a], y[a], kind[a], X[b])
        # outer test rows: base models trained on the whole outer training part
        meta_te = np.column_stack([_fit_and_score(make, mtype, X[tr], y[tr], kind[tr], X[te])
                                   for make, mtype in base.values()])
        stacker = LogisticRegression(max_iter=1000).fit(meta_tr, y[tr])
        out[te] = stacker.predict_proba(meta_te)[:, 1]
    return out

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

def cv_anomaly_scores(make_model, X, kind, folds, normal_quantile=0.99):
    """Out-of-fold anomaly scores from a model trained on NORMAL training rows only.
    Each fold's scores are shifted so that its cut-off (the 99th percentile of normal
    training scores) sits at 0.5, matching score_report's threshold."""
    X, kind = np.asarray(X), np.asarray(kind)
    scores = np.zeros(len(kind), dtype=float)
    for train_idx, test_idx in folds:
        normal_train = train_idx[kind[train_idx] == "normal"]
        model = make_model()
        model.fit(X[normal_train])
        cutoff = np.quantile(-model.score_samples(X[normal_train]), normal_quantile)
        scores[test_idx] = -model.score_samples(X[test_idx]) - cutoff + 0.5
    return scores