# ml/explainability.py
"""
ml/explainability.py
---------------------
Phase 5 Model Explainability Engine for SecureSight.

Provides:
  - Tree-based feature importance
  - Model-agnostic Permutation Importance (sklearn)
  - SHAP-based global and local explanations (optional: graceful fallback)

The explainability API is intentionally pluggable so that a future Phase 7
integration can swap out the heuristic local explanations for true SHAP values.

RULES (from Phase 5 spec §36, §37):
  * Never fabricate explanations.
  * Always prefer actual model-derived importance when available.
  * Fall back to permutation importance when tree importance is unavailable.
  * Local explanations must come from SHAP or explicit permutation-based methods.
"""

import os
import json
import logging
import warnings
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

# Optional SHAP import (graceful fallback)
try:
    import shap  # type: ignore
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    shap = None


# ---------- Global Feature Importance ----------

def global_feature_importance(
    model: Any,
    X_val: pd.DataFrame,
    y_val: Optional[pd.Series] = None,
    feature_names: Optional[List[str]] = None,
    method: str = "auto",
    permutation_n_repeats: int = 5,
    scoring: str = "roc_auc",
    random_state: int = 42,
    n_jobs: int = -1,
) -> Dict[str, float]:
    """
    Compute global feature importance ranking.

    Priority when method == "auto":
      1) native tree ``feature_importances_`` on model or pipeline step
      2) Permutation importance (requires ``y_val``)

    Returns dict sorted by descending importance.
    """
    feature_names = list(feature_names or list(X_val.columns))
    importance: np.ndarray

    use_tree_native = method in ("auto", "tree")
    use_permutation = method in ("auto", "permutation")

    if use_tree_native:
        importance = _extract_tree_importance(model)
    else:
        importance = None

    if importance is None and use_permutation and y_val is not None:
        try:
            r = permutation_importance(
                model, X_val, y_val,
                n_repeats=permutation_n_repeats,
                random_state=random_state,
                scoring=scoring,
                n_jobs=n_jobs,
            )
            importance = r.importances_mean
        except Exception:
            importance = None

    if importance is None:
        return {}

    # Normalize to [0, 1] if any positive values
    vals = np.asarray(importance, dtype=float).ravel()
    if len(vals) < len(feature_names):
        # Pad in case extraction missed something
        padded = np.zeros(len(feature_names), dtype=float)
        padded[:len(vals)] = vals
        vals = padded
    elif len(vals) > len(feature_names):
        vals = vals[:len(feature_names)]

    # Clamp negatives to 0 (permutation importance can be negative from noise)
    vals_clamped = np.clip(vals, 0.0, None)
    total = float(vals_clamped.sum())
    if total > 0:
        scaled = vals_clamped / total
    else:
        scaled = vals_clamped

    out = {
        feature_names[i]: round(float(scaled[i]), 6)
        for i in range(len(feature_names))
    }
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _extract_tree_importance(model: Any) -> Optional[np.ndarray]:
    """Walk sklearn pipelines / calibrators / voting wrappers to find native feature_importances_."""
    try:
        if hasattr(model, "feature_importances_"):
            return np.asarray(model.feature_importances_, dtype=float)
        # CalibratedClassifierCV wraps a prefit estimator
        if hasattr(model, "estimator"):
            inner = _extract_tree_importance(model.estimator)
            if inner is not None:
                return inner
        # VotingClassifier aggregates estimators
        if hasattr(model, "estimators_"):
            # Average feature importances from all tree-based estimators
            collected = []
            for est in model.estimators_:
                fi = _extract_tree_importance(est)
                if fi is not None:
                    collected.append(fi)
            if collected:
                stacked = np.vstack([np.asarray(c) for c in collected])
                return stacked.mean(axis=0)
        # sklearn Pipeline: walk named_steps
        if hasattr(model, "named_steps"):
            for _, step in model.named_steps.items():
                fi = _extract_tree_importance(step)
                if fi is not None:
                    return fi
        # StackingEnsembleClassifier (custom): fitted_base_estimators_
        if hasattr(model, "fitted_base_estimators_"):
            collected = []
            for est in model.fitted_base_estimators_.values():
                fi = _extract_tree_importance(est)
                if fi is not None:
                    collected.append(fi)
            if collected:
                stacked = np.vstack([np.asarray(c) for c in collected])
                return stacked.mean(axis=0)
    except Exception:
        logging.getLogger(__name__).info("native_importance_unavailable")
    return None


# ---------- SHAP Explainability (optional) ----------

def _is_shapable(model: Any) -> bool:
    """Best-effort check for whether a SHAP tree/linear explainer makes sense."""
    if not HAS_SHAP:
        return False
    try:
        if hasattr(model, "predict_proba"):
            return True
    except Exception:
        return False
    return False


def shap_explain_sample(
    model: Any,
    X_sample: pd.DataFrame,
    background: Optional[pd.DataFrame] = None,
    feature_names: Optional[List[str]] = None,
    top_k: int = 5,
    class_index: int = 1,
) -> Optional[Dict[str, Any]]:
    """
    Compute SHAP local explanations for a single sample.

    Returns:
      {
        "base_value": float,
        "predicted_probability": float,
        "explanations": [ {"feature": str, "value": float, "shap_value": float, "impact": "positive"|"negative"}, ... ]
      }
      or None if SHAP is unavailable.
    """
    if not HAS_SHAP or not _is_shapable(model):
        return None

    feature_names = list(feature_names or list(X_sample.columns))
    if background is None:
        # Use the sample itself as a minimal background; callers should pass a training summary for better results.
        background = X_sample

    try:
        # Use TreeExplainer when possible (fast + exact), else KernelExplainer as fallback
        explainer = None
        try:
            # Attempt tree explainer first — works with most sklearn tree ensembles + XGBoost
            explainer = shap.TreeExplainer(model)
        except Exception:
            try:
                explainer = shap.LinearExplainer(model, background)
            except Exception:
                # Fallback: use sampling/kernel explainer on predict_proba
                def model_fn(X):
                    probs = model.predict_proba(X)
                    if probs.ndim == 2 and probs.shape[1] > class_index:
                        return probs[:, class_index]
                    return probs.ravel()
                explainer = shap.KernelExplainer(model_fn, background)

        if explainer is None:
            return None

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sv = explainer.shap_values(X_sample)

        # Normalize output shape: TreeExplainer for binary classifiers may return list[2]
        if isinstance(sv, list):
            sv_arr = np.asarray(sv[class_index])
        else:
            sv_arr = np.asarray(sv)

        if sv_arr.ndim == 3:
            # Some SHAP versions: (n_classes, n_samples, n_features)
            sv_arr = sv_arr[class_index]

        shap_row = sv_arr[-1, :]  # last sample
        base_value = getattr(explainer, "expected_value", None)
        if isinstance(base_value, list) or isinstance(base_value, np.ndarray):
            base_value = float(np.asarray(base_value).ravel()[class_index])
        elif base_value is not None:
            base_value = float(base_value)

        # Predicted probability
        try:
            proba = float(model.predict_proba(X_sample.iloc[-1:])[0, class_index])
        except Exception:
            proba = float("nan")

        # Build per-feature records and rank by |SHAP|
        records: List[Tuple[float, str, float, str]] = []
        for i, fname in enumerate(feature_names):
            sval = float(shap_row[i]) if i < len(shap_row) else 0.0
            try:
                fval = float(X_sample.iloc[-1, i])
            except Exception:
                fval = 0.0
            impact = "positive" if sval > 0 else "negative" if sval < 0 else "neutral"
            records.append((abs(sval), fname, fval, sval, impact))

        records.sort(key=lambda t: t[0], reverse=True)
        explanations = []
        for _, fname, fval, sval, impact in records[:top_k]:
            explanations.append({
                "feature": fname,
                "value": fval,
                "shap_value": round(sval, 6),
                "impact": impact,
            })

        return {
            "base_value": base_value,
            "predicted_probability": round(proba, 5),
            "top_k": top_k,
            "class_index": class_index,
            "explanations": explanations,
            "engine": "shap",
        }
    except Exception:
        return None


# ---------- Permutation-based Local Explanation (fallback) ----------

def permutation_explain_sample(
    model: Any,
    X_sample: pd.DataFrame,
    feature_names: Optional[List[str]] = None,
    top_k: int = 5,
    class_index: int = 1,
    baseline: Optional[np.ndarray] = None,
) -> Optional[Dict[str, Any]]:
    """
    Naive single-sample local explanation by leave-one-feature-out perturbation.

    This is a deterministic fallback when SHAP is not installed. The "impact"
    value is signed delta in predicted probability vs the baseline prediction.
    """
    feature_names = list(feature_names or list(X_sample.columns))
    try:
        base_proba = float(model.predict_proba(X_sample.iloc[-1:])[0, class_index])
    except Exception:
        return None

    results: List[Tuple[float, str, float, float, str]] = []
    sample_row = X_sample.iloc[[-1]].copy()

    for i, fname in enumerate(feature_names):
        perturbed = sample_row.copy()
        original_val = float(perturbed.iloc[0, i])
        # Zero is an explicit perturbation, not an assertion of missingness.
        # Use an observed training baseline when supplied by the caller.
        perturbed.iloc[0, i] = float(baseline[i]) if baseline is not None else 0.0
        try:
            p_proba = float(model.predict_proba(perturbed)[0, class_index])
        except Exception:
            return None
        delta = base_proba - p_proba  # positive means feature pushed score up
        impact = "positive" if delta > 1e-6 else "negative" if delta < -1e-6 else "neutral"
        results.append((abs(delta), fname, original_val, delta, impact))

    results.sort(key=lambda t: t[0], reverse=True)
    explanations = []
    for _, fname, fval, delta, impact in results[:top_k]:
        explanations.append({
            "feature": fname,
            "value": fval,
            "delta_probability": round(delta, 6),
            "impact": impact,
        })

    return {
        "predicted_probability": round(base_proba, 5),
        "top_k": top_k,
        "class_index": class_index,
        "explanations": explanations,
        "engine": "permutation_perturbation",
    }


# ---------- Public convenience: explain one sample ----------

def explain_sample(
    model: Any,
    feature_dict: Dict[str, float],
    feature_names: Optional[List[str]] = None,
    background_df: Optional[pd.DataFrame] = None,
    top_k: int = 5,
    preferred_engine: str = "auto",
) -> Dict[str, Any]:
    """
    Unified public API for local sample explanation.

    Output schema matches Phase 5 §38 example (and is forward-compatible with Phase 7):
    {
      "prediction": "phishing"|"legitimate",
      "probability": float,
      "explanations": [ { "feature": str, "value": float, "impact": "positive"|"negative" }, ... ],
      "engine": "shap" | "permutation_perturbation",
    }
    """
    feature_names = list(feature_names or list(feature_dict.keys()))
    try:
        values = [float(feature_dict[name]) for name in feature_names]
        if not np.isfinite(values).all():
            raise ValueError("Nonfinite feature")
    except (KeyError, TypeError, ValueError):
        return {"prediction":None, "probability":None, "explanations":[], "engine":None}
    X_sample = pd.DataFrame([values], columns=feature_names)

    result: Dict[str, Any] = {
        "prediction": None,
        "probability": None,
        "explanations": [],
        "engine": None,
    }

    # Try SHAP first
    if preferred_engine in ("auto", "shap"):
        shap_res = shap_explain_sample(
            model, X_sample,
            background=background_df,
            feature_names=feature_names,
            top_k=top_k,
        )
        if shap_res is not None:
            prob = shap_res.get("predicted_probability")
            result["engine"] = "shap"
            result["probability"] = prob
            result["prediction"] = ("phishing" if prob >= 0.5 else "legitimate") if prob is not None and np.isfinite(prob) else None
            # Map SHAP explanations to Phase 5 schema
            simple = []
            for e in shap_res.get("explanations", []):
                simple.append({
                    "feature": e["feature"],
                    "value": e["value"],
                    "impact": e["impact"],
                })
            result["explanations"] = simple
            result["shap_detail"] = shap_res
            return result

    # Fallback: permutation perturbation
    perm_res = permutation_explain_sample(
        model, X_sample,
        feature_names=feature_names,
        top_k=top_k,
    )
    if perm_res is not None:
        prob = perm_res.get("predicted_probability")
        result["engine"] = "permutation_perturbation"
        result["probability"] = prob
        result["prediction"] = ("phishing" if prob >= 0.5 else "legitimate") if prob is not None and np.isfinite(prob) else None
        simple = []
        for e in perm_res.get("explanations", []):
            simple.append({
                "feature": e["feature"],
                "value": e["value"],
                "impact": e["impact"],
            })
        result["explanations"] = simple
        result["perm_detail"] = perm_res
    return result


# ---------- Utility: serialize explainability artifacts to reports/ml/ ----------

def save_explainability_artifacts(
    output_dir: str,
    model: Any,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    feature_names: Optional[List[str]] = None,
    sample_feature_dicts: Optional[List[Dict[str, float]]] = None,
) -> None:
    """Persist global feature importance + sample explanations under reports/ml/."""
    os.makedirs(output_dir, exist_ok=True)
    feature_names = list(feature_names or list(X_val.columns))

    # 1) Global importance (permutation + native combined)
    imp = global_feature_importance(model, X_val, y_val=y_val, feature_names=feature_names)
    with open(os.path.join(output_dir, "feature_importance.json"), "w", encoding="utf-8") as f:
        json.dump(imp, f, indent=2)

    # 2) Per-sample explanations for representative samples
    if sample_feature_dicts:
        sample_explanations = []
        for fd in sample_feature_dicts[:10]:
            sample_explanations.append(explain_sample(
                model, fd, feature_names=feature_names, top_k=5,
            ))
        with open(os.path.join(output_dir, "local_explanations.json"), "w", encoding="utf-8") as f:
            json.dump(sample_explanations, f, indent=2, default=str)
