"""Tests for Streamlit's production configuration and in-process API adapter."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from flask import Flask, jsonify, request

from streamlit_app import main as streamlit_main
from app.services import scans


def test_entrypoint_imports_project_packages_when_run_from_subdirectory():
    entrypoint_dir = Path(streamlit_main.__file__).parent
    completed = subprocess.run(
        [sys.executable, "-c", "import runpy; runpy.run_path('main.py'); import app"],
        cwd=entrypoint_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_repository_packages_take_precedence_over_installed_namesakes():
    assert sys.path[0] == streamlit_main.REPOSITORY_ROOT


def test_deployment_config_fails_closed_without_public_secrets(monkeypatch):
    for name in ("FLASK_SECRET_KEY", "RATELIMIT_STORAGE_URI", "SITE_URL"):
        monkeypatch.delenv(name, raising=False)
    config, missing = streamlit_main.deployment_config()
    assert config is None
    assert missing == ["FLASK_SECRET_KEY", "RATELIMIT_STORAGE_URI", "SITE_URL"]


def test_deployment_config_requires_tls_redis_and_https(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "A1b2C3d4E5f6G7h8" * 3)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "redis://redis.example:6379/0")
    monkeypatch.setenv("SITE_URL", "http://example.streamlit.app")
    config, errors = streamlit_main.deployment_config()
    assert config is None
    assert "TLS-protected rediss://" in errors[0]


def test_deployment_config_rejects_weak_secret_and_example_origin(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "x" * 48)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "rediss://redis.example:6379/0")
    monkeypatch.setenv("SITE_URL", "https://YOUR_APP_NAME.streamlit.app")
    config, errors = streamlit_main.deployment_config()
    assert config is None
    assert "generated value" in errors[0]

    monkeypatch.setenv("FLASK_SECRET_KEY", "A1b2C3d4E5f6G7h8" * 3)
    config, errors = streamlit_main.deployment_config()
    assert config is None
    assert "actual HTTPS origin" in errors[0]


def test_deployment_config_builds_production_settings(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "A1b2C3d4E5f6G7h8" * 3)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "rediss://redis.example:6379/0")
    monkeypatch.setenv("SITE_URL", "https://securesight.streamlit.app/")
    config, errors = streamlit_main.deployment_config()
    assert errors == []
    assert config["APP_ENV"] == "production"
    assert config["SITE_URL"] == "https://securesight.streamlit.app"
    assert config["RATELIMIT_STORAGE_URI"].startswith("rediss://")
    assert config["DASHBOARD_DB_PATH"] == ""


def test_coverage_is_rendered_as_percentage_points():
    assert streamlit_main._coverage_label(65) == "65%"
    assert streamlit_main._coverage_label(0) == "0%"
    assert streamlit_main._coverage_label(100) == "100%"
    assert streamlit_main._coverage_label(None) == "Unavailable"
    assert streamlit_main._coverage_label(101) == "Unavailable"


def test_url_verdict_copy_does_not_claim_unknown_is_safe():
    unknown, level = streamlit_main._url_verdict_text("UNKNOWN")
    assert "finish enough checks" in unknown
    assert level == "info"
    low_risk, level = streamlit_main._url_verdict_text(
        "UNKNOWN", risk_score=1.23, ml_probability=0.012,
        model_available=True, webpage_analyzed=True,
    )
    assert low_risk == "Low risk — no clear threat found"
    assert level == "info"
    assert streamlit_main._url_verdict_text(
        "UNKNOWN", risk_score=1.23, ml_probability=0.012,
        model_available=False, webpage_analyzed=True,
    )[0] != low_risk
    assert streamlit_main._url_verdict_text(
        "UNKNOWN", risk_score=1.23, ml_probability=0.012,
        model_available=True, webpage_analyzed=False,
    )[0] != low_risk
    assert streamlit_main._url_verdict_text("PHISHING")[0].startswith("Unsafe")
    assert streamlit_main._url_verdict_text("SUSPICIOUS")[0].startswith("Suspicious")
    assert streamlit_main._url_verdict_text("LEGITIMATE")[0].startswith("No strong threat")


def test_model_unavailable_reason_is_preserved(monkeypatch):
    class FailedPredictor:
        _loaded = False

        def load(self):
            return {"status": "MODEL_VERSION_MISMATCH"}

    scans._models.cache_clear()
    monkeypatch.setattr(scans, "SecureSightPredictor", FailedPredictor)
    try:
        assert scans._models()["url_load_status"]["status"] == "MODEL_VERSION_MISMATCH"
    finally:
        scans._models.cache_clear()
    assert "runtime or schema" in streamlit_main._model_status_text("MODEL_VERSION_MISMATCH")
    assert "integrity check" in streamlit_main._model_status_text(
        "MODEL_LOAD_FAILED", "CHECKSUM_MISMATCH:model.pkl"
    )


def test_scan_result_preserves_safe_model_failure_reason():
    status = {
        "status": "MODEL_LOAD_FAILED",
        "failure_reason": "CHECKSUM_MISMATCH:model.pkl",
    }
    prediction = scans._unavailable_prediction(status)
    assert prediction == {
        "status": "MODEL_LOAD_FAILED",
        "probability": None,
        "prediction": None,
        "failure_reason": "CHECKSUM_MISMATCH:model.pkl",
    }


def test_model_json_artifact_hashes_are_portable_across_line_endings():
    artifact_dir = Path(streamlit_main.REPOSITORY_ROOT) / "models" / "v5"
    metadata = json.loads(
        (artifact_dir / "model_metadata.json").read_text(encoding="utf-8")
    )
    for name, expected in metadata["artifact_sha256"].items():
        artifact = (artifact_dir / name).read_bytes()
        if name.endswith(".json"):
            assert b"\r\n" not in artifact, f"{name} must stay LF-stable"
        assert hashlib.sha256(artifact).hexdigest() == expected


def test_url_adapter_uses_shared_api(monkeypatch):
    app = Flask(__name__)
    app.add_url_rule("/api/v1/scan", view_func=lambda: jsonify(verdict="UNKNOWN"), methods=["POST"])
    monkeypatch.setattr(streamlit_main, "_flask_app", lambda: app)
    assert streamlit_main._request_url("https://example.com") == {"verdict": "UNKNOWN"}


def test_image_adapter_posts_file_to_shared_api(monkeypatch):
    app = Flask(__name__)

    def media():
        upload = request.files["file"]
        return jsonify(filename=upload.filename, size=len(upload.read()), assessment={"verdict": "UNKNOWN"})

    app.add_url_rule("/api/v1/media/analyze", view_func=media, methods=["POST"])
    monkeypatch.setattr(streamlit_main, "_flask_app", lambda: app)
    result = streamlit_main._request_image("fixture.png", b"image-bytes")
    assert result["filename"] == "fixture.png"
    assert result["size"] == len(b"image-bytes")


def test_email_adapter_polls_ephemeral_bearer_job(monkeypatch):
    app = Flask(__name__)

    def submit():
        assert request.files["file"].filename == "fixture.eml"
        return jsonify(job_id="a" * 32, token="temporary-token", poll_url="/api/v1/email/jobs/" + "a" * 32), 202

    def poll(job_id):
        assert job_id == "a" * 32
        assert request.headers["Authorization"] == "Bearer temporary-token"
        return jsonify(state="PARTIAL", result={"risk": {"verdict": "UNKNOWN"}})

    app.add_url_rule("/api/v1/email/analyze", view_func=submit, methods=["POST"])
    app.add_url_rule("/api/v1/email/jobs/<job_id>", view_func=poll, methods=["GET"])
    monkeypatch.setattr(streamlit_main, "_flask_app", lambda: app)
    assert streamlit_main._request_email("fixture.eml", b"From: a@example.com\n\nhello") == {
        "risk": {"verdict": "UNKNOWN"}
    }


def test_email_adapter_reports_document_extraction_failure(monkeypatch):
    app = Flask(__name__)

    def reject_scanned_pdf():
        assert request.files["file"].filename == "fixture.pdf"
        return jsonify(analysis_status="FAILED", error={"code": "DOCUMENT_TEXT_UNAVAILABLE"}), 422

    app.add_url_rule("/api/v1/email/analyze", view_func=reject_scanned_pdf, methods=["POST"])
    monkeypatch.setattr(streamlit_main, "_flask_app", lambda: app)
    try:
        streamlit_main._request_email("fixture.pdf", b"%PDF-fixture")
    except RuntimeError as exc:
        assert "No readable text" in str(exc)
        assert "scanned PDF" in str(exc)
    else:
        raise AssertionError("Expected a readable-text explanation for scanned PDF")
