"""Tests for Streamlit's production configuration and in-process API adapter."""
import hashlib
import json
import subprocess
import sys
from contextlib import nullcontext
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


def test_community_cloud_lock_installs_checksum_pinned_image_model():
    root = Path(streamlit_main.REPOSITORY_ROOT)
    cloud_requirements = (root / "streamlit_app" / "requirements.txt").read_text(encoding="utf-8")
    runtime_requirements = (root / "requirements-runtime.lock").read_text(encoding="utf-8")
    model_path = root / "models" / "image_origin" / "image_origin_cnn.onnx"
    metadata = json.loads((root / "models" / "image_origin" / "evaluation.json").read_text(encoding="utf-8"))

    assert "-r ../requirements-runtime.lock" in cloud_requirements
    assert "onnxruntime==1.23.2" in runtime_requirements
    assert model_path.is_file()
    assert hashlib.sha256(model_path.read_bytes()).hexdigest() == metadata["model_sha256"]


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


def test_email_result_uses_plain_language_evidence_without_fabricating_ml():
    result = streamlit_main._email_result_summary({
        "analysis_status": "PARTIAL",
        "body_analysis": {"snippet": "redacted"},
        "risk": {"verdict": "UNKNOWN", "risk_score": None},
        "evidence": [
            {"indicator": "AUTHENTICATION_UNVERIFIED", "evidence_type": "MISSING"},
            {"indicator": "HTML_LINK_DOMAIN_MISMATCH", "evidence_type": "OBSERVED"},
        ],
    })
    assert result["headline"] == "Warning signs found — verify before acting"
    assert "Displayed link and actual destination" in result["findings"][0]
    assert result["authentication_note"] is True
    assert result["email_model"] == "Unavailable"
    assert result["email_estimate"] is None
    assert result["risk_score"] is None


def test_email_result_never_calls_unscored_content_confirmed_safe():
    result = streamlit_main._email_result_summary({
        "analysis_status": "PARTIAL",
        "body_analysis": {"snippet": "redacted"},
        "risk": {"verdict": "UNKNOWN", "risk_score": None},
        "evidence": [],
    })
    assert "model verdict unavailable" in result["headline"]
    assert "not a model-based verdict" in result["action"]
    assert "safe" not in result["headline"].casefold()


def test_experimental_email_model_alerts_only_at_saved_threshold():
    result = streamlit_main._email_result_summary({
        "analysis_status": "PARTIAL",
        "risk": {"verdict": "UNKNOWN", "risk_score": None},
        "evidence": [],
        "email_model": {"status": "EXPERIMENTAL", "estimate": 0.95,
                        "threshold_crossed": True},
    })
    assert result["level"] == "warning"
    assert "Warning signs" in result["headline"]
    assert result["email_estimate"] == 0.95
    assert result["email_model_alert"] is True


def test_below_threshold_email_model_never_means_legitimate():
    result = streamlit_main._email_result_summary({
        "analysis_status": "ANALYZED",
        "risk": {"verdict": "UNKNOWN", "risk_score": None},
        "evidence": [],
        "email_model": {"status": "EXPERIMENTAL", "estimate": 0.2,
                        "threshold_crossed": False},
    })
    assert result["level"] == "info"
    assert "did not cross" in result["headline"]
    assert "not treat this result as legitimate or safe" in result["action"]
    assert result["verdict_label"] == "Needs review"
    assert result["status_detail"] == "Model below warning threshold"


def test_image_summary_separates_unknown_threat_verdict_from_unavailable_origin_model():
    result = streamlit_main._image_result_summary({
        "analysis_status": "PARTIAL",
        "assessment": {"verdict": "UNKNOWN", "risk_score": None},
        "artifact": {"format": "PNG", "filename": "sample.png"},
        "metadata": {"status": "ANALYZED", "width": 1254, "height": 1254,
                     "exif_present": False},
        "forensics": {
            "status": "ANALYZED",
            "recompression_mean_absolute_error": 3.1,
            "high_frequency_energy_fraction": 0.53,
            "local_texture_variances": [1.2, 2.4],
        },
        "quality": {"status": "ANALYZED"},
        "synthetic_media": {"analysis_status": "MODEL_UNAVAILABLE",
                            "synthetic_probability": None},
        "provenance": {"status": "ABSENT"},
        "ocr": {"status": "ANALYZED", "words": [{"text": "sample"}]},
        "qr": {"status": "ANALYZED", "items": []},
        "linked_analysis": [],
        "evidence": [{"id": "media.provenance_absent"}],
        "investigation": {"coverage": {"unavailable": ["ai_detector"]}},
    })
    assert result["headline"] == "Threat screening needs review"
    assert result["level"] == "info"
    assert result["model_value"] == "Unavailable"
    assert result["model_detail"] == "Experimental AI-pattern estimate unavailable"
    assert result["model_available"] is False
    assert result["risk_value"] == "Not scored"
    assert result["dimensions"] == "1,254 × 1,254 px"
    assert result["image_name"] == "sample.png"
    assert result["provenance"] == "No C2PA provenance found"
    assert result["ocr_word_count"] == 1
    assert result["qr_count"] == 0
    assert result["evidence_count"] == 1
    assert result["measurement_count"] == 3
    assert ("High frequency energy fraction", "53.00%") in result["measurements"]


def test_image_summary_shows_experimental_ai_pattern_estimate_without_calling_it_real_or_fake():
    result = streamlit_main._image_result_summary({
        "analysis_status": "PARTIAL",
        "assessment": {"verdict": "UNKNOWN", "risk_score": 18.0},
        "artifact": {"format": "PNG", "filename": "synthetic.png"},
        "metadata": {"status": "ANALYZED", "width": 512, "height": 512},
        "quality": {"status": "ANALYZED"},
        "synthetic_media": {
            "analysis_status": "EXPERIMENTAL_ESTIMATE",
            "model_score": 0.91,
            "classification": "AI_GENERATED_PATTERN",
            "decision_threshold": 0.709269,
            "calibrated": False,
            "test_metrics": {"balanced_accuracy": 0.875625},
        },
        "provenance": {"status": "ABSENT"},
        "ocr": {"status": "ANALYZED", "words": []},
        "qr": {"status": "ANALYZED", "items": []},
        "linked_analysis": [],
        "evidence": [],
    })
    assert result["headline"] == "Threat screening needs review"
    assert result["pill"] == "AI-origin estimate available"
    assert result["model_value"] == "91.0%"
    assert result["model_available"] is True
    assert result["model_classification"] == "AI_GENERATED_PATTERN"
    assert result["model_detail"] == "AI-generation pattern flagged · experimental score"
    assert result["model_threshold"] == 0.709269
    assert result["risk_value"] == "18.0/100"


def test_image_summary_does_not_claim_valid_signature_is_trusted_without_trust():
    result = streamlit_main._image_result_summary({
        "assessment": {"verdict": "UNKNOWN", "risk_score": None},
        "provenance": {"status": "VALID", "trusted": False},
        "synthetic_media": {"analysis_status": "MODEL_UNAVAILABLE"},
    })
    assert result["provenance"] == "Signed, but issuer trust is unverified"
    assert result["headline"] == "Threat screening needs review"


def test_image_result_panel_renders_reference_style_summary_and_evidence(monkeypatch):
    rendered = []
    monkeypatch.setattr(streamlit_main.st, "markdown", lambda value, **kwargs: rendered.append(str(value)))
    monkeypatch.setattr(streamlit_main.st, "info", lambda value: rendered.append(str(value)))
    monkeypatch.setattr(streamlit_main.st, "write", lambda value: rendered.append(str(value)))
    monkeypatch.setattr(streamlit_main.st, "caption", lambda value: rendered.append(str(value)))
    monkeypatch.setattr(streamlit_main.st, "json", lambda value, **kwargs: rendered.append("json"))
    monkeypatch.setattr(
        streamlit_main.st,
        "expander",
        lambda label, **kwargs: (rendered.append(str(label)) or nullcontext()),
    )
    result = {
        "assessment": {"verdict": "UNKNOWN", "risk_score": None},
        "artifact": {"format": "PNG", "filename": "mock.png"},
        "metadata": {"status": "ANALYZED", "width": 400, "height": 300,
                     "exif_present": False},
        "quality": {"status": "ANALYZED"},
        "synthetic_media": {"analysis_status": "MODEL_UNAVAILABLE"},
        "provenance": {"status": "ABSENT"},
        "ocr": {"status": "ANALYZED", "words": []},
        "qr": {"status": "ANALYZED", "items": []},
        "linked_analysis": [],
    }

    streamlit_main._show_result(result, "image")

    output = "\n".join(rendered)
    assert "Threat screening needs review" in output
    assert "Experimental AI-pattern score" in output
    assert "Forensic signals" in output
    assert "Measured properties · no anomaly verdict" in output
    assert "No C2PA provenance found" in output
    assert "View technical diagnostic breakdown" in output
    assert "does not detect all deepfakes" in output


def test_email_result_summary_provides_plain_language_card_and_diagnostic_values():
    result = streamlit_main._email_result_summary({
        "analysis_status": "PARTIAL",
        "message": {"original_bytes": 512},
        "body_analysis": {
            "snippet": "Please verify your payment today.",
            "features": {"urgency": True, "credentials": False},
        },
        "risk": {"verdict": "UNKNOWN", "risk_score": None},
        "urls": [{"url": "https://example.invalid"}],
        "attachments": [{"filename": "notice.pdf"}],
        "evidence": [{
            "indicator": "SOCIAL_ENGINEERING_LANGUAGE",
            "evidence_type": "OBSERVED",
        }],
        "email_model": {
            "status": "EXPERIMENTAL",
            "estimate": 0.167,
            "threshold_crossed": False,
        },
    })

    assert result["verdict_label"] == "Needs review"
    assert result["snippet"] == "Please verify your payment today."
    assert result["email_estimate"] == 0.167
    assert result["warning_count"] == 1
    assert result["context_pattern_count"] == 1
    assert result["link_count"] == 1
    assert result["attachment_count"] == 1
    assert result["message_bytes"] == 512


def test_email_result_reports_failed_analysis_without_verdict():
    result = streamlit_main._email_result_summary({
        "analysis_status": "FAILED",
        "risk": {"verdict": "UNKNOWN", "risk_score": None},
        "evidence": [],
    })
    assert result["headline"] == "Email analysis failed — no result was produced"
    assert result["level"] == "error"


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
        return jsonify(filename=upload.filename, size=len(upload.read()),
                       artifact={"format": "PNG"}, assessment={"verdict": "UNKNOWN"})

    app.add_url_rule("/api/v1/media/analyze", view_func=media, methods=["POST"])
    monkeypatch.setattr(streamlit_main, "_flask_app", lambda: app)
    result = streamlit_main._request_image("fixture.png", b"image-bytes")
    assert result["filename"] == "fixture.png"
    assert result["size"] == len(b"image-bytes")
    assert result["artifact"]["filename"] == "fixture.png"


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
        assert "after PDF OCR" in str(exc)
    else:
        raise AssertionError("Expected a readable-text explanation for scanned PDF")


def test_email_adapter_retries_one_transient_capacity_rejection(monkeypatch):
    app = Flask(__name__)
    submissions = {"count": 0}

    def submit():
        submissions["count"] += 1
        if submissions["count"] == 1:
            response = jsonify(error={"code": "PROVIDER_UNAVAILABLE"})
            response.status_code = 503
            response.headers["Retry-After"] = "1"
            return response
        return jsonify(job_id="b" * 32, token="temporary-token", poll_url="/api/v1/email/jobs/" + "b" * 32), 202

    def poll(job_id):
        return jsonify(state="PARTIAL", result={"risk": {"verdict": "UNKNOWN"}})

    app.add_url_rule("/api/v1/email/analyze", view_func=submit, methods=["POST"])
    app.add_url_rule("/api/v1/email/jobs/<job_id>", view_func=poll, methods=["GET"])
    monkeypatch.setattr(streamlit_main, "_flask_app", lambda: app)
    monkeypatch.setattr(streamlit_main.time, "sleep", lambda _: None)

    result = streamlit_main._request_email("fixture.eml", b"Subject: test\n\nhello")

    assert submissions["count"] == 2
    assert result == {"risk": {"verdict": "UNKNOWN"}}


def test_email_adapter_explains_persistent_capacity_rejection(monkeypatch):
    app = Flask(__name__)

    def submit():
        response = jsonify(error={"code": "PROVIDER_UNAVAILABLE"})
        response.status_code = 503
        response.headers["Retry-After"] = "1"
        return response

    app.add_url_rule("/api/v1/email/analyze", view_func=submit, methods=["POST"])
    monkeypatch.setattr(streamlit_main, "_flask_app", lambda: app)
    monkeypatch.setattr(streamlit_main.time, "sleep", lambda _: None)

    try:
        streamlit_main._request_email("fixture.eml", b"Subject: test\n\nhello")
    except RuntimeError as exc:
        assert "scanner is busy" in str(exc).lower()
        assert "was not queued" in str(exc).lower()
    else:
        raise AssertionError("Expected a clear message for a busy scanner")
