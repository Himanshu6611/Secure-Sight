# ml/ensemble.py
"""
ml/ensemble.py
--------------
Out-of-Fold (OOF) Stacking Ensemble Engine for SecureSight Phase 5.
Combines predictions from base estimators (LR, RF, XGBoost) using cross-validated
Out-of-Fold prediction matrices to train a Logistic Regression Meta-Learner without data leakage.
"""

from typing import Dict, List, Any, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, StratifiedGroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.base import BaseEstimator, ClassifierMixin, clone


class StackingEnsembleClassifier(BaseEstimator, ClassifierMixin):
    """
    Production-grade Stacking Ensemble Classifier using Out-of-Fold (OOF) predictions.
    """

    def __init__(self, base_estimators: Dict[str, BaseEstimator], n_folds: int = 5, random_state: int = 42):
        self.base_estimators = base_estimators
        self.n_folds = n_folds
        self.random_state = random_state
        self.fitted_base_estimators_: Dict[str, BaseEstimator] = {}
        self.meta_learner_: Optional[LogisticRegression] = None
        self.classes_ = np.array([0, 1])

    def fit(self, X: pd.DataFrame, y: pd.Series, groups=None):
        X_arr = X if isinstance(X, pd.DataFrame) else np.array(X)
        y_arr = y.values if isinstance(y, pd.Series) else np.array(y)

        estimator_names = list(self.base_estimators.keys())
        n_samples = len(X_arr)
        n_estimators = len(estimator_names)

        # Matrix to hold Out-of-Fold prediction probabilities
        oof_predictions = np.zeros((n_samples, n_estimators))

        cv = (StratifiedGroupKFold if groups is not None else StratifiedKFold)(n_splits=self.n_folds, shuffle=True, random_state=self.random_state)
        self.fold_audit_ = []

        # Generate Out-of-Fold Predictions for Meta-Learner
        for fold, (train_idx, val_idx) in enumerate(cv.split(X_arr, y_arr, groups)):
            X_tr = X_arr.iloc[train_idx] if isinstance(X_arr, pd.DataFrame) else X_arr[train_idx]
            X_va = X_arr.iloc[val_idx] if isinstance(X_arr, pd.DataFrame) else X_arr[val_idx]
            y_tr = y_arr[train_idx]
            overlap = set(np.array(groups)[train_idx]) & set(np.array(groups)[val_idx]) if groups is not None else set()
            if overlap:
                raise ValueError("OOF domain overlap")
            self.fold_audit_.append(dict(train_rows=len(train_idx), validation_rows=len(val_idx), domain_overlap=len(overlap)))

            for idx, name in enumerate(estimator_names):
                fold_model = clone(self.base_estimators[name])
                fold_model.fit(X_tr, y_tr)
                if hasattr(fold_model, "predict_proba"):
                    probs = fold_model.predict_proba(X_va)[:, 1]
                else:
                    probs = fold_model.predict(X_va)
                oof_predictions[val_idx, idx] = probs

        # Train Logistic Regression Meta-Learner on OOF predictions
        self.meta_learner_ = LogisticRegression(solver="lbfgs", C=1.0, random_state=self.random_state)
        self.meta_learner_.fit(oof_predictions, y_arr)

        # Fit final base estimators on full training dataset
        self.fitted_base_estimators_ = {}
        for name, est in self.base_estimators.items():
            full_model = clone(est)
            full_model.fit(X_arr, y_arr)
            self.fitted_base_estimators_[name] = full_model

        return self

    def _get_base_probabilities(self, X: pd.DataFrame) -> np.ndarray:
        X_arr = X if isinstance(X, pd.DataFrame) else np.array(X)
        estimator_names = list(self.base_estimators.keys())
        n_samples = len(X_arr)
        base_probs = np.zeros((n_samples, len(estimator_names)))

        for idx, name in enumerate(estimator_names):
            model = self.fitted_base_estimators_[name]
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X_arr)[:, 1]
            else:
                probs = model.predict(X_arr)
            base_probs[:, idx] = probs

        return base_probs

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        base_probs = self._get_base_probabilities(X)
        meta_prob_1 = self.meta_learner_.predict_proba(base_probs)[:, 1]
        meta_prob_0 = 1.0 - meta_prob_1
        return np.column_stack((meta_prob_0, meta_prob_1))

    def predict(self, X: pd.DataFrame, threshold: float = 0.50) -> np.ndarray:
        probs = self.predict_proba(X)[:, 1]
        return (probs >= threshold).astype(int)
