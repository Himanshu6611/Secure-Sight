"""Validated trusted local artifacts; failures never create a legitimate verdict."""
import hashlib
import json
import pathlib
import time
import warnings
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.exceptions import InconsistentVersionWarning
from ml.features import FEATURE_ORDER, URL_FEATURE_ORDER, FEATURE_SCHEMA_VERSION

V5_MODEL_DIR = str(pathlib.Path(__file__).resolve().parents[1] / "models" / "v5")
ERR_MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
ERR_MODEL_VERSION_MISMATCH = "MODEL_VERSION_MISMATCH"
ERR_MODEL_LOAD_FAILED = "MODEL_LOAD_FAILED"
ERR_SCHEMA_MISMATCH = "FEATURE_SCHEMA_MISMATCH"
ERR_INVALID_FEATURES = "INVALID_FEATURE_VECTOR"
ERR_MISSING_REQUIRED_FEATURE = "MISSING_REQUIRED_FEATURE"
ERR_PREPROCESSING_FAILED = "PREPROCESSING_FAILED"
ERR_PREDICTION_FAILED = "PREDICTION_FAILED"


def error(status, **details):
    return dict(status=status, prediction=None, probability=None, **details)


class SecureSightPredictor:
    def __init__(self, model_dir=V5_MODEL_DIR, strict_version=True):
        self.model_dir = model_dir
        self.strict_version = strict_version
        self.model = self.preprocessor = None
        self.metadata = self.feature_schema = {}
        self.threshold = .5
        self.calibration_method = None
        self._loaded = False
        self._load_time_ms = 0

    def load(self):
        self._loaded = False
        folder = pathlib.Path(self.model_dir)
        if not (folder / "model.pkl").is_file():
            return error(ERR_MODEL_NOT_FOUND, failure_reason="MODEL_ARTIFACT_MISSING")
        try:
            self.metadata = json.loads((folder / "model_metadata.json").read_text(encoding="utf8"))
            self.feature_schema = json.loads((folder / "feature_schema.json").read_text(encoding="utf8"))
            if self.metadata.get("model_version") != "5.1.1" or self.metadata.get("label_mapping") != {"0":"legitimate", "1":"phishing"}:
                return error(ERR_MODEL_VERSION_MISMATCH, failure_reason="MODEL_METADATA_VERSION_OR_LABEL_MISMATCH")
            if self.feature_schema.get("feature_order") != FEATURE_ORDER or self.feature_schema.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
                return error(ERR_SCHEMA_MISMATCH, failure_reason="FEATURE_SCHEMA_MISMATCH")
            if self.metadata.get("environment", {}).get("scikit_learn_version") != sklearn.__version__:
                return error(ERR_MODEL_VERSION_MISMATCH, failure_reason="SCIKIT_LEARN_VERSION_MISMATCH")
            for name in ["model.pkl", "preprocessor.pkl", "threshold.json", "feature_schema.json"]:
                expected = self.metadata.get("artifact_sha256", {}).get(name)
                if not expected:
                    return error(ERR_MODEL_LOAD_FAILED, failure_reason=f"CHECKSUM_METADATA_MISSING:{name}")
                if hashlib.sha256((folder/name).read_bytes()).hexdigest() != expected:
                    return error(ERR_MODEL_LOAD_FAILED, failure_reason=f"CHECKSUM_MISMATCH:{name}")
            self.threshold = float(json.loads((folder/"threshold.json").read_text())["threshold"])
            if not 0 < self.threshold < 1:
                return error(ERR_MODEL_LOAD_FAILED, failure_reason="MODEL_THRESHOLD_INVALID")
            start = time.perf_counter()
            with warnings.catch_warnings():
                warnings.simplefilter("error", InconsistentVersionWarning)
                self.model = joblib.load(folder/"model.pkl")
                self.preprocessor = joblib.load(folder/"preprocessor.pkl")
            if list(self.model.classes_) != [0,1] or not self.metadata.get("preprocessing_embedded"):
                return error(ERR_MODEL_LOAD_FAILED, failure_reason="MODEL_CLASSES_OR_PREPROCESSING_MISMATCH")
            self._load_time_ms = (time.perf_counter()-start)*1000
            self.calibration_method = self.metadata.get("calibration", {}).get("method")
            self._loaded = True
            return dict(status="OK", **self.describe())
        except Exception as exc:
            self.model = self.preprocessor = None
            return error(ERR_MODEL_LOAD_FAILED, failure_reason=f"MODEL_DESERIALIZATION_ERROR:{type(exc).__name__}")

    def _expected_features(self):
        return FEATURE_ORDER

    def _validate_feature_vector(self, features):
        if not isinstance(features, dict):
            return False, [], ERR_INVALID_FEATURES, None
        if set(features) - set(FEATURE_ORDER):
            return False, [], ERR_SCHEMA_MISMATCH, None
        missing = [k for k in URL_FEATURE_ORDER if k not in features or features[k] is None]
        if missing:
            return False, [], ERR_MISSING_REQUIRED_FEATURE, missing
        values = []
        for name in FEATURE_ORDER:
            value = features.get(name)
            if value is None:
                values.append(np.nan)
                continue
            if isinstance(value, (list, dict)):
                return False, [], ERR_INVALID_FEATURES, None
            try:
                number = float(value)
                if not np.isfinite(number) or number < -1e-8:
                    return False, [], ERR_INVALID_FEATURES, None
                values.append(max(0., number))
            except (ValueError, TypeError, OverflowError):
                return False, [], ERR_INVALID_FEATURES, None
        if float(features.get("url_len", 0)) <= 0 or float(features.get("hostname_len", 0)) <= 0:
            return False, [], ERR_INVALID_FEATURES, None
        return True, values, None, None

    def predict(self, feature_dict, include_explanations=True, explanation_top_k=5):
        if not self._loaded or self.model is None:
            return error(ERR_MODEL_NOT_FOUND)
        ok, values, code, missing = self._validate_feature_vector(feature_dict)
        if not ok:
            result = error(code)
            if missing:
                result["missing_features"] = missing
            return result
        frame = pd.DataFrame([values], columns=FEATURE_ORDER)
        try:
            start = time.perf_counter()
            probability = float(self.model.predict_proba(frame)[0,1])
            if not np.isfinite(probability) or not 0 <= probability <= 1:
                return error(ERR_PREDICTION_FAILED)
            result = dict(status="OK", prediction="phishing" if probability >= self.threshold else "legitimate",
                probability=round(probability,6), threshold=self.threshold, model_version="5.1.1",
                feature_schema_version=FEATURE_SCHEMA_VERSION, latency_ms=round((time.perf_counter()-start)*1000,2),
                model_validated=True, calibration_method=self.calibration_method,
                model_scope="URL lexical classification; domain and webpage evidence scored separately",
                unavailable_features=[k for k,v in zip(FEATURE_ORDER,values) if not np.isfinite(v)])
            if include_explanations:
                try:
                    result.update(self._local_explanation(frame, feature_dict, probability, explanation_top_k))
                except Exception:
                    # An optional explanation failure does not erase a valid prediction.
                    result.update(explanation_status="UNAVAILABLE", explanations=[])
            return result
        except Exception:
            return error(ERR_PREDICTION_FAILED)

    def _local_explanation(self, frame, feature_dict, probability, top_k):
        start = time.perf_counter()
        count = min(10, max(1, int(top_k)))
        medians = self.metadata.get("training_feature_medians", {})
        baseline = np.asarray([medians[name] for name in URL_FEATURE_ORDER], dtype=float)
        if not np.isfinite(baseline).all() or (baseline < 0).any():
            raise ValueError("Training baseline unavailable")
        variants = pd.concat([frame]*len(URL_FEATURE_ORDER), ignore_index=True)
        for i, name in enumerate(URL_FEATURE_ORDER):
            variants.loc[i,name] = baseline[i]
        perturbed = self.model.predict_proba(variants)[:,1]
        if not np.isfinite(perturbed).all() or (perturbed < 0).any() or (perturbed > 1).any():
            raise ValueError("Invalid perturbation probabilities")
        deltas = probability-perturbed
        ranked = sorted(range(len(URL_FEATURE_ORDER)), key=lambda i: (-abs(deltas[i]), URL_FEATURE_ORDER[i]))[:count]
        return {"explanation_status": "AVAILABLE",
            "explanation_method": "feature_median_perturbation; model sensitivity, not causal attribution",
            "explanations": [dict(feature=URL_FEATURE_ORDER[i], value=feature_dict[URL_FEATURE_ORDER[i]],
                contribution=round(float(deltas[i]),6), baseline_value=float(baseline[i]),
                perturbed_probability=round(float(perturbed[i]),6),
                impact="positive" if round(float(deltas[i]),6)>0 else "negative" if round(float(deltas[i]),6)<0 else "neutral") for i in ranked],
            "explanation_latency_ms": round((time.perf_counter()-start)*1000,3)}

    def predict_batch(self, feature_dicts, include_explanations=False):
        return [self.predict(f,include_explanations) for f in feature_dicts]

    def describe(self):
        return dict(loaded=self._loaded, model_version=self.metadata.get("model_version"),
            feature_schema_version=self.feature_schema.get("feature_schema_version"), n_features=len(FEATURE_ORDER),
            threshold=self.threshold, calibration=self.calibration_method, load_time_ms=round(self._load_time_ms,2))
