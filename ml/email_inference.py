"""Checksum-verified experimental email classifier inference.

This research candidate only supports an advisory estimate. Its output must
never be used to label an email legitimate or safe.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
from pathlib import Path
from typing import Any

FEATURES = (
    "length",
    "word_count",
    "keyword_hits",
    "url_count",
    "exclamation_count",
    "question_count",
    "digit_count",
    "entropy",
)
MODEL_VERSION = "email-research-v1"
MODEL_SHA256 = "24a3626899539b819504ca6b144e76cc4f8f7f82b65fe4921819ae805d5a4b02"
ALERT_THRESHOLD = 0.936420918060679
MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "email_staging" / "email_model_research.pkl"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as model_file:
        for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=1)
def _load_model() -> tuple[Any | None, str]:
    if not MODEL_PATH.is_file():
        return None, "MODEL_NOT_FOUND"
    try:
        if _sha256(MODEL_PATH) != MODEL_SHA256:
            return None, "MODEL_CHECKSUM_MISMATCH"
        import joblib

        model = joblib.load(MODEL_PATH)
        classes = list(getattr(model, "classes_", []))
        if classes != [0, 1] or not callable(getattr(model, "predict_proba", None)):
            return None, "MODEL_SCHEMA_INVALID"
        return model, "OK"
    except Exception:
        # A broken research artifact must not prevent deterministic email checks.
        return None, "MODEL_LOAD_FAILED"


def predict_email(text: str) -> dict[str, Any]:
    """Return an experimental estimate, or an explicit unavailable status."""
    model, status = _load_model()
    if model is None:
        return {"status": status, "model_version": MODEL_VERSION, "estimate": None,
                "alert_threshold": ALERT_THRESHOLD, "threshold_crossed": None,
                "scope": "experimental_email_pattern_estimate"}
    try:
        import pandas as pd
        from utils.email_extraction import extract_email_features

        features = extract_email_features(text[:65536])
        row = pd.DataFrame([[features[name] for name in FEATURES]], columns=FEATURES)
        estimate = float(model.predict_proba(row)[0, 1])
        if not 0 <= estimate <= 1:
            raise ValueError("model estimate outside probability bounds")
    except Exception:
        return {"status": "INFERENCE_FAILED", "model_version": MODEL_VERSION,
                "estimate": None, "alert_threshold": ALERT_THRESHOLD,
                "threshold_crossed": None, "scope": "experimental_email_pattern_estimate"}
    return {"status": "EXPERIMENTAL", "model_version": MODEL_VERSION,
            "estimate": estimate, "alert_threshold": ALERT_THRESHOLD,
            "threshold_crossed": estimate >= ALERT_THRESHOLD,
            "scope": "experimental_email_pattern_estimate",
            "limitations": [
                "Uses eight aggregate text features, not semantic language understanding.",
                "A below-threshold result does not establish that an email is safe.",
                "Dataset licensing, label provenance, collection time and campaign review remain open.",
            ]}
