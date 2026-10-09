# ml/models.py
"""
ml/models.py
------------
Base Estimators & Hyperparameter Tuning Engine for SecureSight Phase 5.
Implements Logistic Regression baseline, Random Forest, Decision Tree/Extra Trees,
and XGBoost (with graceful fallback if XGBoost package is omitted).

Supports both GridSearchCV (deterministic, small grid) and RandomizedSearchCV
(larger search spaces). Per-model tuning is driven by `tuning_strategy`.
"""

import logging
from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV, StratifiedKFold
from scipy.stats import loguniform, randint, uniform

# Optional XGBoost import with graceful fallback
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    xgb = None
    HAS_XGBOOST = False


DEFAULT_TUNING = "randomized"  # "grid" | "randomized"
DEFAULT_N_ITER = 8


def _tune(estimator, param_grid, X_train, y_train, cv, scoring: str = "roc_auc",
          strategy: str = DEFAULT_TUNING, n_iter: int = DEFAULT_N_ITER,
          random_state: int = 42, n_jobs: int = -1):
    """Run either GridSearchCV or RandomizedSearchCV, return best estimator + info."""
    strategy = (strategy or "randomized").lower()
    if strategy == "grid":
        gs = GridSearchCV(
            estimator, param_grid,
            cv=cv, scoring=scoring, n_jobs=n_jobs, refit=True,
        )
    else:
        # For randomized, convert list-valued grids to choice distributions where possible.
        dists = {}
        for k, v in param_grid.items():
            if isinstance(v, list):
                if len(v) == 1:
                    dists[k] = v
                else:
                    # Keep as list — RandomizedSearchCV treats list as categorical.
                    dists[k] = v
            else:
                dists[k] = v
        gs = RandomizedSearchCV(
            estimator, dists,
            n_iter=min(n_iter, 50),
            cv=cv, scoring=scoring, n_jobs=n_jobs, refit=True,
            random_state=random_state,
        )
    gs.fit(X_train, y_train)
    info = {
        "tuning_strategy": strategy,
        "best_params": gs.best_params_,
        "cv_auc": float(gs.best_score_),
    }
    # Also record per-fold stats when feasible
    try:
        cv_res = getattr(gs, "cv_results_", None)
        if cv_res is not None:
            mean_test = cv_res.get("mean_test_score")
            std_test = cv_res.get("std_test_score")
            if mean_test is not None and std_test is not None:
                best_idx = int(getattr(gs, "best_index_", 0))
                info["cv_auc_mean"] = round(float(mean_test[best_idx]), 5)
                info["cv_auc_std"] = round(float(std_test[best_idx]), 5)
    except Exception:
        logging.getLogger(__name__).warning("optional_tuning_statistics_unavailable")
    return gs.best_estimator_, info


def train_logistic_regression(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    cv_folds: int = 5,
    random_state: int = 42,
    tuning_strategy: str = DEFAULT_TUNING,
    n_jobs: int = 1,
    n_iter: int = DEFAULT_N_ITER,
) -> Tuple[Pipeline, Dict[str, Any]]:
    """
    Train calibrated Logistic Regression baseline with feature scaling pipeline
    and hyperparameter tuning.
    """
    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(
            solver="lbfgs",
            max_iter=1000,
            class_weight="balanced",
            random_state=random_state,
        )),
    ])

    if tuning_strategy == "grid":
        param_grid = {"lr__C": [0.1, 1.0, 5.0]}
    else:
        param_grid = {"lr__C": loguniform(1e-2, 1e1)}

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    best_est, info = _tune(pipe, param_grid, X_train, y_train, cv,
                           strategy=tuning_strategy, random_state=random_state,
                           n_jobs=n_jobs, n_iter=n_iter)
    # Simplify top-level info for backward compatibility
    best_C = info["best_params"].get("lr__C")
    info["C"] = best_C

    return best_est, info


def train_random_forest(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    cv_folds: int = 5,
    random_state: int = 42,
    tuning_strategy: str = DEFAULT_TUNING,
    n_jobs: int = 1,
    n_iter: int = DEFAULT_N_ITER,
) -> Tuple[RandomForestClassifier, Dict[str, Any]]:
    """
    Train tuned Random Forest Classifier.
    """
    rf = RandomForestClassifier(
        random_state=random_state,
        n_jobs=n_jobs,
        class_weight="balanced",
    )

    if tuning_strategy == "grid":
        param_grid = {
            "n_estimators": [100, 200],
            "max_depth": [15, 20, None],
            "min_samples_split": [2, 5],
        }
    else:
        param_grid = {
            "n_estimators": randint(80, 260),
            "max_depth": [12, 18, None],
            "min_samples_split": randint(2, 8),
            "min_samples_leaf": randint(1, 5),
        }

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    return _tune(rf, param_grid, X_train, y_train, cv,
                strategy=tuning_strategy, random_state=random_state,
                n_jobs=n_jobs, n_iter=n_iter)


def train_xgboost(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    cv_folds: int = 5,
    random_state: int = 42,
    tuning_strategy: str = DEFAULT_TUNING,
    n_jobs: int = 1,
    n_iter: int = DEFAULT_N_ITER,
) -> Tuple[Any, Dict[str, Any]]:
    """
    Train tuned XGBoost Classifier (or ExtraTreesClassifier if xgboost is not installed).
    """
    if HAS_XGBOOST:
        model = xgb.XGBClassifier(
            random_state=random_state,
            eval_metric="logloss",
            n_jobs=n_jobs,
        )
        if tuning_strategy == "grid":
            param_grid = {
                "n_estimators": [100, 200],
                "max_depth": [6, 10],
                "learning_rate": [0.05, 0.1],
            }
        else:
            param_grid = {
                "n_estimators": randint(80, 260),
                "max_depth": randint(4, 12),
                "learning_rate": uniform(0.04, 0.18),
                "subsample": uniform(0.7, 0.3),
                "colsample_bytree": uniform(0.6, 0.4),
                "min_child_weight": randint(1, 7),
            }
        engine_label = "XGBoost"
    else:
        model = ExtraTreesClassifier(
            random_state=random_state,
            n_jobs=n_jobs,
            class_weight="balanced",
        )
        if tuning_strategy == "grid":
            param_grid = {
                "n_estimators": [100, 200],
                "max_depth": [15, 20],
            }
        else:
            param_grid = {
                "n_estimators": randint(100, 260),
                "max_depth": [15, 20, None],
                "min_samples_split": randint(2, 8),
            }
        engine_label = "ExtraTreesFallback"

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    best_est, info = _tune(model, param_grid, X_train, y_train, cv,
                           strategy=tuning_strategy, random_state=random_state,
                           n_jobs=n_jobs, n_iter=n_iter)
    info["engine"] = engine_label
    return best_est, info
