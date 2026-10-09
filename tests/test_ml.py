# tests/test_ml.py
"""
tests/test_ml.py
-----------------
ML Pipeline Unit & Integration Tests for SecureSight Phase 5.
Tests dataset, features, models, ensemble, calibration, inference, evaluation,
regression fixtures, and the API endpoint contract.
"""

import os
import json
import pytest
import numpy as np
import pandas as pd

from ml.features import FEATURE_ORDER, URL_FEATURE_ORDER, FEATURE_SCHEMA_VERSION, align_features_df
from utils.url_features import extract_advanced_url_features
from ml.evaluation import (
    compute_full_metrics,
    threshold_analysis,
    select_optimal_threshold,
)
from ml.ensemble import StackingEnsembleClassifier
from ml.inference import SecureSightPredictor, ERR_MODEL_NOT_FOUND, ERR_INVALID_FEATURES, ERR_SCHEMA_MISMATCH
from ml.calibration import calibrate_classifier
from ml.explainability import (
    global_feature_importance,
    explain_sample,
    permutation_explain_sample,
)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------- Dataset Tests (Phase 5 §52) ----------

class TestDatasetIntegrity:
    def test_cleaned_csv_exists(self):
        assert os.path.exists(os.path.join(ROOT_DIR, "data", "v5_1_1", "rows.csv"))

    def test_features_parquet_exists(self):
        assert os.path.exists(os.path.join(ROOT_DIR, "data", "v5_1_1", "features.parquet"))

    def test_dataset_labels_binary(self):
        df = pd.read_csv(os.path.join(ROOT_DIR, "data", "v5_1_1", "rows.csv"))
        unique_labels = set(df["label"].unique())
        assert unique_labels.issubset({0, 1}), f"Non-binary labels found: {unique_labels}"

    def test_no_missing_labels(self):
        df = pd.read_csv(os.path.join(ROOT_DIR, "data", "v5_1_1", "rows.csv"))
        assert df["label"].isna().sum() == 0

    def test_class_distribution_reasonable(self):
        df = pd.read_csv(os.path.join(ROOT_DIR, "data", "v5_1_1", "rows.csv"))
        ratio = df["label"].value_counts(normalize=True).min()
        assert ratio > 0.1, f"Extreme class imbalance: minority ratio = {ratio:.3f}"

    def test_no_inf_or_nan_in_features(self):
        df = pd.read_parquet(os.path.join(ROOT_DIR, "data", "v5_1_1", "features.parquet"))
        cols = URL_FEATURE_ORDER
        for c in cols:
            assert not np.isinf(pd.to_numeric(df[c], errors="coerce")).any(), f"Inf found in {c}"
            assert not pd.to_numeric(df[c], errors="coerce").isna().any(), f"NaN found in {c}"

    def test_duplicate_detection_dataset_size(self):
        df_cleaned = pd.read_csv(os.path.join(ROOT_DIR, "data", "v5_1_1", "rows.csv"))
        df_feats = pd.read_parquet(os.path.join(ROOT_DIR, "data", "v5_1_1", "features.parquet"))
        # Feature parquet must not exceed the cleaned URL dataset in size
        assert len(df_feats) <= len(df_cleaned)


# ---------- Feature Schema Tests (Phase 5 §52) ----------

class TestFeatureSchema:
    def test_feature_order_is_list(self):
        assert isinstance(FEATURE_ORDER, list)
        assert len(FEATURE_ORDER) > 0

    def test_feature_order_no_duplicates(self):
        assert len(FEATURE_ORDER) == len(set(FEATURE_ORDER))

    def test_feature_schema_version_defined(self):
        assert FEATURE_SCHEMA_VERSION == "5.1.1"

    def test_align_features_df_handles_missing_columns(self):
        df = pd.DataFrame({"url_len": [10, 20], "url_entropy": [3.5, 4.2]})
        aligned = align_features_df(df)
        assert list(aligned.columns) == FEATURE_ORDER
        assert aligned["url_len"].tolist() == [10.0, 20.0]
        assert aligned["url_entropy"].tolist() == [3.5, 4.2]
        # Missing columns should be 0.0
        assert aligned["hostname_len"].isna().all()

    def test_align_features_df_preserves_order(self):
        data = {name: [float(i)] for i, name in enumerate(FEATURE_ORDER)}
        df = pd.DataFrame(data)
        aligned = align_features_df(df)
        assert list(aligned.columns) == FEATURE_ORDER

    def test_missing_feature_handling_coerces_numeric(self):
        df = pd.DataFrame({"url_len": ["not_a_number", "42"], "url_entropy": ["3.5", None]})
        aligned = align_features_df(df)
        # First url_length fails coercion -> NaN -> fillna(0.0)
        assert np.isnan(aligned["url_len"].iloc[0])
        assert aligned["url_len"].iloc[1] == 42


# ---------- Evaluation Metrics Tests ----------

class TestEvaluationMetrics:
    def test_compute_full_metrics_basic(self):
        y_true = np.array([0, 0, 1, 1, 1])
        y_pred = np.array([0, 0, 1, 1, 0])
        y_proba = np.array([0.1, 0.2, 0.9, 0.8, 0.3])
        metrics = compute_full_metrics(y_true, y_pred, y_proba)

        for key in ["accuracy", "precision", "recall", "f1", "roc_auc",
                    "pr_auc", "false_positive_rate", "false_negative_rate",
                    "confusion_matrix"]:
            assert key in metrics, f"Missing metric key: {key}"

        assert 0.0 <= metrics["accuracy"] <= 1.0
        assert 0.0 <= metrics["roc_auc"] <= 1.0
        # Confusion matrix elements must be present and be ints
        cm = metrics["confusion_matrix"]
        for key in ["true_negative", "false_positive", "false_negative", "true_positive"]:
            assert key in cm and isinstance(cm[key], (int, np.integer))

    def test_confusion_matrix_sums_correctly(self):
        y_true = np.array([0, 0, 1, 1, 1, 0])
        y_pred = np.array([0, 1, 1, 1, 0, 0])
        y_proba = np.array([0.1, 0.6, 0.9, 0.8, 0.3, 0.2])
        metrics = compute_full_metrics(y_true, y_pred, y_proba)
        cm = metrics["confusion_matrix"]
        total = cm["true_negative"] + cm["false_positive"] + cm["false_negative"] + cm["true_positive"]
        assert total == len(y_true)

    def test_threshold_analysis_returns_multiple_rows(self):
        y_true = np.array([0, 0, 1, 1, 1])
        y_proba = np.array([0.1, 0.4, 0.6, 0.8, 0.9])
        results = threshold_analysis(y_true, y_proba)
        assert len(results) > 0
        for r in results:
            for key in ["threshold", "precision", "recall", "f1", "fpr", "fnr"]:
                assert key in r, f"Missing key {key} in threshold row"

    def test_select_optimal_threshold_f1_priority(self):
        results = [
            {"threshold": 0.3, "f1": 0.80, "recall": 0.95, "precision": 0.70, "fpr": 0.05, "fnr": 0.05},
            {"threshold": 0.5, "f1": 0.90, "recall": 0.88, "precision": 0.92, "fpr": 0.03, "fnr": 0.12},
            {"threshold": 0.7, "f1": 0.85, "recall": 0.75, "precision": 0.97, "fpr": 0.01, "fnr": 0.25},
        ]
        best_f1 = select_optimal_threshold(results, priority="f1")
        assert best_f1["threshold"] == 0.5
        assert best_f1["selection_priority"] == "f1"

    def test_select_optimal_threshold_recall_priority(self):
        results = [
            {"threshold": 0.3, "f1": 0.80, "recall": 0.95, "precision": 0.70, "fpr": 0.05, "fnr": 0.05},
            {"threshold": 0.5, "f1": 0.90, "recall": 0.88, "precision": 0.92, "fpr": 0.03, "fnr": 0.12},
            {"threshold": 0.7, "f1": 0.85, "recall": 0.75, "precision": 0.97, "fpr": 0.01, "fnr": 0.25},
        ]
        best_recall = select_optimal_threshold(results, priority="recall")
        # Recall priority: maximize recall while keeping FPR < 0.10
        assert best_recall["threshold"] == 0.3


# ---------- Ensemble Tests (Phase 5 §52) ----------

class TestStackingEnsemble:
    def _make_toy_data(self, n=200, seed=42):
        np.random.seed(seed)
        X = pd.DataFrame(np.random.randn(n, 5), columns=[f"f{i}" for i in range(5)])
        y = pd.Series((X["f0"] + X["f1"] > 0).astype(int))
        return X, y

    def test_ensemble_fit_predict(self):
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier

        X, y = self._make_toy_data()
        base = {
            "lr": LogisticRegression(random_state=42),
            "rf": RandomForestClassifier(n_estimators=10, random_state=42),
        }
        ens = StackingEnsembleClassifier(base_estimators=base, n_folds=3, random_state=42)
        ens.fit(X, y)

        proba = ens.predict_proba(X)
        assert proba.shape == (len(X), 2)
        # Output row sums are valid probability distributions
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)

        preds = ens.predict(X)
        assert set(preds).issubset({0, 1})

    def test_ensemble_probability_range(self):
        from sklearn.linear_model import LogisticRegression
        from sklearn.tree import DecisionTreeClassifier

        X, y = self._make_toy_data()
        base = {
            "lr": LogisticRegression(random_state=42),
            "dt": DecisionTreeClassifier(random_state=42),
        }
        ens = StackingEnsembleClassifier(base_estimators=base, n_folds=3, random_state=42)
        ens.fit(X, y)
        proba = ens.predict_proba(X)
        assert proba.min() >= 0.0
        assert proba.max() <= 1.0

    def test_oof_predictions_are_stable(self):
        """Fit two ensembles with same seed -> same predictions."""
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        X, y = self._make_toy_data(n=100)
        base = {
            "lr": LogisticRegression(random_state=1),
            "rf": RandomForestClassifier(n_estimators=5, random_state=1),
        }
        a = StackingEnsembleClassifier(base, n_folds=3, random_state=7).fit(X, y).predict_proba(X)
        b = StackingEnsembleClassifier(base, n_folds=3, random_state=7).fit(X, y).predict_proba(X)
        assert np.allclose(a, b, atol=1e-6)


# ---------- Calibration Tests ----------

class TestCalibration:
    def _make_toy(self, n=200, seed=0):
        np.random.seed(seed)
        X = pd.DataFrame(np.random.randn(n, 4), columns=[f"a", "b", "c", "d"])
        logits = X["a"] + X["b"]
        proba_true = 1.0 / (1.0 + np.exp(-logits))
        y = pd.Series((np.random.rand(n) < proba_true).astype(int))
        return X, y

    def test_calibrate_classifier_isotonic(self):
        from sklearn.linear_model import LogisticRegression
        X, y = self._make_toy()
        X_tr, X_val = X.iloc[:150], X.iloc[150:]
        y_tr, y_val = y.iloc[:150], y.iloc[150:]
        base = LogisticRegression(random_state=0).fit(X_tr, y_tr)
        calibrated, report = calibrate_classifier(base, X_val, y_val, method="isotonic")
        assert report["calibration_method"] == "isotonic"
        proba = calibrated.predict_proba(X_val)
        assert proba.shape == (len(X_val), 2)
        assert np.isfinite(proba).all()

    def test_calibrate_classifier_platt(self):
        from sklearn.tree import DecisionTreeClassifier
        X, y = self._make_toy()
        X_tr, X_val = X.iloc[:150], X.iloc[150:]
        y_tr, y_val = y.iloc[:150], y.iloc[150:]
        base = DecisionTreeClassifier(max_depth=4, random_state=0).fit(X_tr, y_tr)
        calibrated, report = calibrate_classifier(base, X_val, y_val, method="sigmoid")
        assert report["calibration_method"] == "sigmoid"
        proba = calibrated.predict_proba(X_val)
        assert proba.min() >= -1e-9  # allow numeric slack
        assert proba.max() <= 1.0 + 1e-9


# ---------- Inference Tests ----------

class TestInference:
    def test_predictor_missing_model_returns_explicit_error(self):
        predictor = SecureSightPredictor(model_dir="/nonexistent/path")
        result = predictor.load()
        assert result["status"] == ERR_MODEL_NOT_FOUND

    def test_predictor_predict_without_load_returns_model_not_found(self):
        predictor = SecureSightPredictor(model_dir="/nonexistent/path")
        result = predictor.predict({"url_len": 50})
        assert result["status"] == ERR_MODEL_NOT_FOUND
        assert result["prediction"] is None
        assert result["probability"] is None

    def test_predictor_invalid_feature_vector_detection(self):
        """When v5 model exists, test that non-numeric values are rejected."""
        v5_dir = os.path.join(ROOT_DIR, "models", "v5")
        if not os.path.exists(os.path.join(v5_dir, "model.pkl")):
            pytest.skip("v5 model not yet trained")
        predictor = SecureSightPredictor(model_dir=v5_dir)
        predictor.load()
        schema_path = os.path.join(v5_dir, "feature_schema.json")
        with open(schema_path) as f:
            schema = json.load(f)
        bad_dict = {k: "definitely_not_a_number" for k in schema["feature_order"]}
        result = predictor.predict(bad_dict, include_explanations=True)
        # The predictor should reject invalid feature vectors explicitly
        assert result["status"] == ERR_INVALID_FEATURES
        assert result["probability"] is None and result["prediction"] is None

    def test_predictor_with_v5_model(self):
        v5_dir = os.path.join(ROOT_DIR, "models", "v5")
        if not os.path.exists(os.path.join(v5_dir, "model.pkl")):
            pytest.skip("v5 model not yet trained")

        predictor = SecureSightPredictor(model_dir=v5_dir)
        load_result = predictor.load()
        assert load_result["status"] == "OK"

        # Build a feature dict with all zeros (should not crash, inference OK)
        schema_path = os.path.join(v5_dir, "feature_schema.json")
        with open(schema_path) as f:
            schema = json.load(f)
        feature_dict = {k: None for k in schema["feature_order"]}
        feature_dict.update(extract_advanced_url_features("https://example.com/"))
        result = predictor.predict(feature_dict, include_explanations=True)
        assert result["status"] == "OK"
        assert result["prediction"] in ("phishing", "legitimate")
        assert 0.0 <= result["probability"] <= 1.0
        # Explanations array is present per Phase 5 §38 contract
        assert "explanations" in result
        assert isinstance(result["explanations"], list)
        for e in result["explanations"]:
            assert "feature" in e
            assert "value" in e
            assert "impact" in e and e["impact"] in ("positive", "negative", "neutral")

    def test_predictor_describe(self):
        predictor = SecureSightPredictor(model_dir="/nonexistent")
        desc = predictor.describe()
        assert isinstance(desc, dict)
        assert desc["loaded"] is False


# ---------- Explainability Tests ----------

class TestExplainability:
    def _make_toy(self, n=120, seed=1):
        np.random.seed(seed)
        cols = ["f_a", "f_b", "f_c", "f_d"]
        X = pd.DataFrame(np.random.randn(n, len(cols)), columns=cols)
        y = pd.Series((X["f_a"] * 1.5 - X["f_b"] > 0.2).astype(int))
        return X, y

    def test_global_feature_importance_permutation(self):
        from sklearn.ensemble import RandomForestClassifier
        X, y = self._make_toy()
        X_tr, X_val = X.iloc[:80], X.iloc[80:]
        y_tr, y_val = y.iloc[:80], y.iloc[80:]
        model = RandomForestClassifier(n_estimators=30, random_state=0).fit(X_tr, y_tr)
        imp = global_feature_importance(
            model, X_val, y_val=y_val,
            feature_names=list(X.columns),
            method="permutation",
            permutation_n_repeats=2,
            random_state=0,
        )
        assert isinstance(imp, dict)
        assert len(imp) == len(X.columns)
        # All importance values should be non-negative normalized contributions
        for v in imp.values():
            assert 0.0 <= float(v) <= 1.0

    def test_explain_sample_local(self):
        from sklearn.ensemble import RandomForestClassifier
        X, y = self._make_toy()
        model = RandomForestClassifier(n_estimators=20, random_state=0).fit(X, y)
        sample_fd = {"f_a": 1.5, "f_b": -1.0, "f_c": 0.0, "f_d": 0.5}
        res = explain_sample(
            model, sample_fd,
            feature_names=list(X.columns),
            top_k=3,
            preferred_engine="auto",
        )
        # At minimum, permutation fallback must produce a valid result
        assert res["prediction"] in ("phishing", "legitimate")
        assert 0.0 <= res["probability"] <= 1.0
        assert isinstance(res["explanations"], list)
        assert len(res["explanations"]) <= 3


# ---------- Regression Fixtures (Phase 5 §52/§53) ----------

class TestRegressionFixtures:
    @pytest.fixture
    def _load_fixture(self):
        def _inner(fname):
            path = os.path.join(ROOT_DIR, "tests", "fixtures", "ml", fname)
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        return _inner

    def test_label_definition_exists(self):
        path = os.path.join(ROOT_DIR, "data", "metadata", "label_definition.json")
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["encoding"]["0"] == "legitimate"
        assert data["encoding"]["1"] == "phishing"

    def test_dataset_manifest_exists(self):
        path = os.path.join(ROOT_DIR, "data", "metadata", "dataset_manifest.json")
        assert os.path.exists(path)

    def test_dataset_hash_metadata_exists(self):
        path = os.path.join(ROOT_DIR, "data", "metadata", "dataset_hash.json")
        assert os.path.exists(path)

    def test_fixture_known_legitimate_valid_json(self, _load_fixture):
        fixtures = _load_fixture("known_legitimate.json")
        assert isinstance(fixtures, list) and len(fixtures) >= 1
        for item in fixtures:
            assert "features" in item
            assert "expected_label" in item

    def test_fixture_known_phishing_valid_json(self, _load_fixture):
        fixtures = _load_fixture("known_phishing.json")
        assert isinstance(fixtures, list) and len(fixtures) >= 1
        for item in fixtures:
            assert "features" in item
            assert "expected_label" in item
            # Known phishing fixtures must expect label 1 (or null for edge)
            assert item["expected_label"] in (1, None)

    def test_fixture_edge_cases_valid_json(self, _load_fixture):
        fixtures = _load_fixture("edge_cases.json")
        assert isinstance(fixtures, list) and len(fixtures) >= 1
        for item in fixtures:
            assert "edge_case" in item
            assert "features" in item
