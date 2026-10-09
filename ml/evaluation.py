# ml/evaluation.py
"""
ml/evaluation.py
-----------------
Comprehensive Model Evaluation Engine for SecureSight Phase 5.
Computes accuracy, precision, recall, F1, ROC-AUC, PR-AUC, FPR, FNR,
confusion matrix, threshold analysis, and feature importance.
"""

import json
import logging
import os
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
    precision_recall_curve,
    roc_curve,
)
from sklearn.inspection import permutation_importance


def compute_full_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
) -> Dict[str, Any]:
    """
    Compute all Phase 5 evaluation metrics from true labels, hard predictions,
    and predicted probabilities.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_proba)),
        "pr_auc": float(average_precision_score(y_true, y_proba)),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def threshold_analysis(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    thresholds: Optional[List[float]] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluate precision, recall, F1, FPR, and FNR at multiple thresholds.
    """
    if thresholds is None:
        thresholds = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]

    results = []
    for t in thresholds:
        y_pred = (y_proba >= t).astype(int)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        results.append({
            "threshold": round(t, 2),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
        })

    return results


def select_optimal_threshold(
    threshold_results: List[Dict[str, Any]],
    priority: str = "f1",
) -> Dict[str, Any]:
    """
    Select the best operating threshold based on priority metric.
    Supported priorities: 'f1', 'recall', 'precision'.
    """
    if not threshold_results:
        return {"threshold": 0.50, "reason": "no_results"}

    if priority == "recall":
        # Maximize recall while keeping FPR < 10%
        candidates = [r for r in threshold_results if r["fpr"] < 0.10]
        if not candidates:
            candidates = threshold_results
        best = max(candidates, key=lambda r: r["recall"])
    elif priority == "precision":
        best = max(threshold_results, key=lambda r: r["precision"])
    else:
        best = max(threshold_results, key=lambda r: r["f1"])

    return {**best, "selection_priority": priority}


def compute_roc_curve_data(
    y_true: np.ndarray,
    y_proba: np.ndarray,
) -> Dict[str, List[float]]:
    """Compute FPR/TPR pairs for ROC curve serialization."""
    fpr, tpr, thresholds = roc_curve(y_true, y_proba)
    # Subsample to keep JSON manageable
    step = max(1, len(fpr) // 200)
    return {
        "fpr": [round(float(v), 5) for v in fpr[::step]],
        "tpr": [round(float(v), 5) for v in tpr[::step]],
    }


def compute_pr_curve_data(
    y_true: np.ndarray,
    y_proba: np.ndarray,
) -> Dict[str, List[float]]:
    """Compute Precision/Recall pairs for PR curve serialization."""
    prec, rec, thresholds = precision_recall_curve(y_true, y_proba)
    step = max(1, len(prec) // 200)
    return {
        "precision": [round(float(v), 5) for v in prec[::step]],
        "recall": [round(float(v), 5) for v in rec[::step]],
    }


def compute_feature_importance(
    model: Any,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    feature_names: List[str],
    n_repeats: int = 5,
    random_state: int = 42,
) -> Dict[str, float]:
    """
    Compute permutation importance for model-agnostic feature ranking.
    Falls back to tree-based feature_importances_ if available.
    """
    importance_dict = {}

    # Try permutation importance first (model-agnostic)
    try:
        n_max = min(8000, len(X_val))
        if len(X_val) > n_max:
            from sklearn.model_selection import train_test_split
            X_perm, _, y_perm, _ = train_test_split(
                X_val, y_val, train_size=n_max,
                stratify=y_val, random_state=random_state,
            )
        else:
            X_perm, y_perm = X_val, y_val
        perm_result = permutation_importance(
            model, X_perm, y_perm,
            n_repeats=max(2, n_repeats // 2),
            random_state=random_state,
            scoring="roc_auc",
            n_jobs=1,
        )
        for i, name in enumerate(feature_names):
            importance_dict[name] = round(float(perm_result.importances_mean[i]), 6)
    except Exception:
        # Fallback: tree-based importance
        try:
            if hasattr(model, "feature_importances_"):
                importances = model.feature_importances_
            elif hasattr(model, "named_steps"):
                # Pipeline: find the estimator step
                for step_name, step_est in model.named_steps.items():
                    if hasattr(step_est, "feature_importances_"):
                        importances = step_est.feature_importances_
                        break
                else:
                    importances = None
            else:
                importances = None

            if importances is not None:
                for i, name in enumerate(feature_names):
                    importance_dict[name] = round(float(importances[i]), 6)
        except Exception:
            logging.getLogger(__name__).warning("optional_evaluation_output_unavailable")

    return dict(sorted(importance_dict.items(), key=lambda x: -x[1]))


def save_evaluation_artifacts(
    output_dir: str,
    metrics: Dict[str, Any],
    threshold_results: List[Dict[str, Any]],
    optimal_threshold: Dict[str, Any],
    roc_data: Dict[str, List[float]],
    pr_data: Dict[str, List[float]],
    feature_importance: Dict[str, float],
    model_comparison: Optional[Dict[str, Dict[str, Any]]] = None,
    classification_report_dict: Optional[Dict[str, Any]] = None,
    calibration_report: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Save all evaluation artifacts as JSON files to reports/ml/ directory.
    """
    os.makedirs(output_dir, exist_ok=True)

    def _dump(name: str, data: Any) -> None:
        path = os.path.join(output_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    _dump("final_evaluation.json", metrics)
    _dump("threshold_analysis.json", threshold_results)
    _dump("optimal_threshold.json", optimal_threshold)
    _dump("roc_curve.json", roc_data)
    _dump("precision_recall_curve.json", pr_data)
    _dump("feature_importance.json", feature_importance)
    _dump("confusion_matrix.json", metrics.get("confusion_matrix", {}))

    if classification_report_dict is not None:
        _dump("classification_report.json", classification_report_dict)

    if calibration_report is not None:
        _dump("calibration_report.json", calibration_report)

    if model_comparison:
        _dump("model_comparison.json", model_comparison)
        # Also save model comparison as CSV for spreadsheet readability
        try:
            import csv
            rows = []
            header_set = False
            header = ["model"]
            for model_name, mdict in model_comparison.items():
                if not isinstance(mdict, dict):
                    continue
                row = {"model": model_name}
                for k, v in mdict.items():
                    if isinstance(v, (int, float, str, bool)) or v is None:
                        row[k] = v
                        if not header_set and k not in header:
                            header.append(k)
                rows.append(row)
                header_set = True
            csv_path = os.path.join(output_dir, "model_comparison.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as cf:
                writer = csv.DictWriter(cf, fieldnames=header, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
        except Exception:
            logging.getLogger(__name__).warning("optional_evaluation_output_unavailable")
