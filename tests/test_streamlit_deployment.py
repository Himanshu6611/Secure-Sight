"""Tests for Streamlit's production configuration and in-process API adapter."""
from flask import Flask, jsonify, request

from streamlit_app import main as streamlit_main


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
