"""Leakage-aware evaluation helpers for the exploratory structured email model."""
from __future__ import annotations

import numpy as np
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbalancedPipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, log_loss, precision_score,
                             recall_score, roc_auc_score)
from sklearn.pipeline import Pipeline


def candidate_models(random_state=20261009):
    """Return comparable models; resampling occurs inside each CV training fold."""
    return {
        "logistic_class_weight": (
            Pipeline([("impute", SimpleImputer(strategy="median")),
                      ("scale", StandardScaler()),
                      ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced",
                                                         random_state=random_state))]),
            {"classifier__C": [0.1, 1.0, 10.0]},
        ),
        "logistic_smote": (
            ImbalancedPipeline([("impute", SimpleImputer(strategy="median")),
                                ("scale", StandardScaler()),
                                ("sampler", SMOTE(random_state=random_state, k_neighbors=3)),
                                ("classifier", LogisticRegression(max_iter=2000, random_state=random_state))]),
            {"classifier__C": [0.1, 1.0, 10.0]},
        ),
        "random_forest_class_weight": (
            Pipeline([("impute", SimpleImputer(strategy="median")),
                      ("classifier", RandomForestClassifier(n_estimators=200, max_depth=20,
                          min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1,
                          random_state=random_state))]),
            {"classifier__max_depth": [12, 20, None]},
        ),
    }


def choose_threshold(labels, probabilities, max_fpr=0.01):
    """Choose maximum validation recall under the documented validation FPR cap."""
    y = np.asarray(labels, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    if len(y) != len(p) or not len(y) or set(np.unique(y)) != {0, 1}:
        raise ValueError("Threshold selection requires aligned validation data with both classes")
    if not np.isfinite(p).all() or ((p < 0) | (p > 1)).any() or not 0 < max_fpr < 1:
        raise ValueError("Threshold inputs are invalid")
    candidates = []
    for threshold in np.unique(np.r_[np.linspace(0.01, 0.99, 99), p]):
        prediction = p >= threshold
        tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if fp + tn else None
        if fpr is not None and fpr <= max_fpr:
            recall = tp / (tp + fn) if tp + fn else 0.0
            precision = tp / (tp + fp) if tp + fp else 0.0
            candidates.append((recall, precision, float(threshold), fpr))
    if not candidates:
        raise ValueError("No validation threshold meets the false-positive-rate constraint")
    recall, precision, threshold, fpr = max(candidates, key=lambda row: (row[0], row[1], row[2]))
    return {"threshold": threshold, "recall": recall, "precision": precision, "fpr": fpr,
            "selection_partition": "threshold_selection", "objective": "maximum recall subject to validation FPR <= 1%"}


def evaluate_binary(labels, probabilities, threshold):
    y = np.asarray(labels, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    if len(y) != len(p) or not len(y) or set(np.unique(y)) != {0, 1}:
        raise ValueError("Evaluation requires aligned labels with both classes")
    if not np.isfinite(p).all() or ((p < 0) | (p > 1)).any():
        raise ValueError("Evaluation probabilities are invalid")
    predicted = p >= threshold
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    return {
        "samples": len(y), "threshold": float(threshold), "accuracy": float(accuracy_score(y, predicted)),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)),
        "f1": float(f1_score(y, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, p)), "average_precision": float(average_precision_score(y, p)),
        "brier_score": float(brier_score_loss(y, p)), "log_loss": float(log_loss(y, p, labels=[0, 1])),
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp),
                             "false_negative": int(fn), "true_positive": int(tp)},
    }
