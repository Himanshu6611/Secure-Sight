from ml import email_inference
import numpy as np


class FakeModel:
    classes_ = [0, 1]

    def __init__(self, estimate):
        self.estimate = estimate
        self.columns = None

    def predict_proba(self, frame):
        self.columns = list(frame.columns)
        return np.array([[1 - self.estimate, self.estimate]])


def test_email_inference_returns_experimental_score_with_training_schema(monkeypatch):
    model = FakeModel(0.97)
    monkeypatch.setattr(email_inference, "_load_model", lambda: (model, "OK"))

    result = email_inference.predict_email("URGENT: verify your account at https://example.invalid")

    assert result["status"] == "EXPERIMENTAL"
    assert result["estimate"] == 0.97
    assert result["threshold_crossed"] is True
    assert model.columns == list(email_inference.FEATURES)
    assert any("does not establish" in item for item in result["limitations"])


def test_email_inference_keeps_model_unavailable_explicit(monkeypatch):
    monkeypatch.setattr(email_inference, "_load_model", lambda: (None, "MODEL_NOT_FOUND"))
    result = email_inference.predict_email("ordinary message")
    assert result["status"] == "MODEL_NOT_FOUND"
    assert result["estimate"] is None
    assert result["threshold_crossed"] is None


def test_email_inference_rejects_out_of_range_estimate(monkeypatch):
    monkeypatch.setattr(email_inference, "_load_model", lambda: (FakeModel(1.2), "OK"))
    result = email_inference.predict_email("ordinary message")
    assert result["status"] == "INFERENCE_FAILED"
    assert result["estimate"] is None


def test_email_model_file_checksum_is_enforced(tmp_path, monkeypatch):
    artifact = tmp_path / "tampered.pkl"
    artifact.write_bytes(b"not the reviewed model")
    monkeypatch.setattr(email_inference, "MODEL_PATH", artifact)
    email_inference._load_model.cache_clear()
    try:
        model, status = email_inference._load_model()
    finally:
        email_inference._load_model.cache_clear()
    assert model is None
    assert status == "MODEL_CHECKSUM_MISMATCH"


def test_scan_response_exposes_email_model_separately_from_observed_risk():
    from app.services.scans import format_email_result

    result, _ = format_email_result({
        "risk": {"verdict": "UNKNOWN"},
        "body_analysis": {"snippet": "redacted", "features": {}},
        "email_model": {"status": "EXPERIMENTAL", "estimate": 0.94,
                        "threshold_crossed": True},
        "explanation": {},
    })
    assert result["model_available"] is True
    assert result["ml_probability"] == 0.94
    assert result["email_model"]["status"] == "EXPERIMENTAL"
    assert result["warnings"] == []
