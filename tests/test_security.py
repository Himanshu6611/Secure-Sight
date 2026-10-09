import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from app import create_app
from app.security.urls import InvalidURL, validate_url
from app.security import outbound


@pytest.mark.parametrize("url", ["https://example.com", "http://example.com/a%20b?q=a%27b", "example.com", "https://例え.jp/path", "https://8.8.8.8"])
def test_valid_urls(url):
    assert validate_url(url).startswith(("http://", "https://"))


@pytest.mark.parametrize("url", [None, 123, [], {}, "", "https://", "file:///etc/passwd", "data:text/html,test",
    "javascript:alert(1)", "vbscript:test", "ftp://example.com", "//example.com", "https://user:pass@example.com",
    "https://example.com:0", "https://example.com:22", "https://example.com:65536", "https://example.com:",
    "https://example.com/\r\nx", "https://example.com/%0d%0a", "https://example.com/%zz", "https://example.com\\@evil.com",
    "http://localhost", "http://local.localhost", "http://internal.local", "http://127.0.0.1", "http://127.1",
    "http://2130706433", "http://0x7f000001", "http://0177.0.0.1", "http://10.0.0.1", "http://172.16.0.1",
    "http://192.168.1.1", "http://169.254.169.254", "http://100.64.0.1", "http://0.0.0.0", "http://224.0.0.1",
    "http://[::1]", "http://[::ffff:127.0.0.1]", "http://[64:ff9b::7f00:1]", "http://[fe80::1%25eth0]",
    "https://example.com/<script>alert(1)</script>", "https://example.com/" + "a" * 2048])
def test_reject_unsafe_urls(url):
    with pytest.raises(InvalidURL):
        validate_url(url)


@pytest.mark.parametrize("body", [[], None, "text", 123, {"url": 123}, {"url": []}, {"url": "https://example.com", "unexpected": 1}])
def test_api_schema(client, body):
    response = client.post("/api/v1/scan", data=json.dumps(body), content_type="application/json")
    assert response.status_code == 400
    assert response.json["error"]["code"]


def test_malformed_json_and_content_type(client):
    assert client.post("/api/v1/scan", data='{', content_type="application/json").status_code == 400
    assert client.post("/api/v1/scan", data='url=test').status_code == 415


def test_api_compatibility(client):
    old = client.post("/api/analyze", json={"url": "https://example.com"})
    new = client.post("/api/v1/scan", json={"url": "https://example.com"})
    assert old.status_code == new.status_code == 200
    for key in ("url", "decision", "status", "ml_probability", "feature_vector", "evidence", "warnings"):
        assert old.json[key] == new.json[key]


def test_health_readiness(client, app):
    assert client.get("/api/v1/health").json == {"status": "healthy"}
    assert client.get("/api/v1/ready").status_code == 200
    app.extensions["models"] = {"url": None, "email": None}
    assert client.get("/api/v1/ready").status_code == 503


def test_payload_limits(client):
    assert client.post("/api/v1/scan", json={"url": "a" * 9000}).status_code == 413
    assert client.post("/", data=b"a" * (6 * 1024 * 1024 + 1)).status_code == 413
    assert client.post("/", data={"check_type": "email", "email_text": "a" * 100001}).status_code == 405


def test_host_origin_and_headers(client, app):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert client.post("/api/v1/scan", json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    app.config["ALLOWED_ORIGINS"] = ["https://frontend.example"]
    response = client.options("/api/v1/scan", headers={"Origin": "https://frontend.example"})
    assert response.headers["Access-Control-Allow-Origin"] == "https://frontend.example"
    assert "Access-Control-Allow-Origin" not in client.get("/api/v1/health", headers={"Origin": "https://evil.example"}).headers
    page = client.get("/")
    assert page.headers["X-Frame-Options"] == "DENY"
    assert page.headers["X-Content-Type-Options"] == "nosniff"
    # no-referrer makes Chromium form POSTs send Origin: null.
    assert page.headers["Referrer-Policy"] == "same-origin"
    assert "'unsafe-inline'" not in page.headers["Content-Security-Policy"].split("script-src ")[1].split(";")[0]
    assert b"onclick=" not in page.data
    assert page.headers["X-Request-ID"] != client.get("/").headers["X-Request-ID"]


def test_same_origin_form_and_null_origin(client, app):
    app.config["TRUSTED_HOSTS"] = ["localhost", "127.0.0.1"]
    response = client.post("/", base_url="http://127.0.0.1:5000", headers={"Origin": "http://127.0.0.1:5000", "Sec-Fetch-Site": "same-origin"},
                           data={"check_type": "email", "email_text": "Hello"})
    assert response.status_code == 405
    assert client.post("/", headers={"Origin": "null"}).status_code == 403


def test_production_headers_and_backend_failure(monkeypatch):
    from limits.storage import MemoryStorage

    class DummyStorage(MemoryStorage):
        def __init__(self, healthy=True):
            super().__init__()
            self.healthy = healthy
        def check(self):
            return self.healthy

    dummy = DummyStorage(True)
    monkeypatch.setattr("flask_limiter._extension.storage_from_string", lambda uri, **kw: dummy)
    monkeypatch.setattr("limits.storage.storage_from_string", lambda uri, **kw: dummy)


    app = create_app({"APP_ENV": "production", "SECRET_KEY": "a" * 48, "SITE_URL": "https://localhost",
                      "ALLOWED_ORIGINS": [], "TRUSTED_HOSTS": ["localhost"], "RATELIMIT_STORAGE_URI": "redis://localhost:6379"})
    response = app.test_client().get("/api/v1/health")
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
    dummy.healthy = False
    assert app.test_client().get("/api/v1/ready").status_code == 503
    with pytest.raises(ValueError, match="storage is unavailable"):
        create_app({"APP_ENV": "production", "SECRET_KEY": "a" * 48, "SITE_URL": "https://localhost",
                    "TRUSTED_HOSTS": ["localhost"], "ALLOWED_ORIGINS": [], "RATELIMIT_STORAGE_URI": "redis://localhost:6379"})



def test_rate_limit_and_forwarded_spoof(monkeypatch):
    app = create_app({"TESTING": True, "APP_ENV": "testing", "SCAN_RATE_LIMIT": "2 per minute",
                      "TRUSTED_HOSTS": ["localhost"], "RATELIMIT_STORAGE_URI": "memory://"})
    client = app.test_client()
    for n in range(2):
        assert client.post("/api/v1/scan", json={}, headers={"X-Forwarded-For": f"1.1.1.{n}"}).status_code == 400
    response = client.post("/api/analyze", json={})
    assert response.status_code == 429
    assert response.headers["Retry-After"]
    assert client.get("/api/v1/health").status_code == 200


def test_capacity_released(client, app):
    slots = app.extensions["scan_slots"]
    for _ in range(app.config["MAX_CONCURRENT_SCANS"]):
        assert slots.acquire(False)
    assert client.post("/api/v1/scan", json={}).status_code == 503
    for _ in range(app.config["MAX_CONCURRENT_SCANS"]):
        slots.release()
    assert client.post("/api/v1/scan", json={}).status_code == 400
    assert client.post("/api/v1/scan", json={}).status_code == 400


def test_errors_and_logs_exclude_sensitive_content(client, app, monkeypatch):
    from app.api import v1
    secret = "password=super-private-token"
    def failed(value):
        raise RuntimeError(secret)
    monkeypatch.setattr(v1, "scan_url", failed)
    log = io.StringIO()
    handler = app.logger.handlers[0]
    original = handler.stream
    handler.setStream(log)
    try:
        response = client.post("/api/v1/scan", json={"url": "https://example.com/?" + secret})
    finally:
        handler.setStream(original)
    assert response.status_code == 500
    assert secret not in response.get_data(as_text=True)
    assert secret not in log.getvalue()
    events = [json.loads(line) for line in log.getvalue().splitlines()]
    assert any(e.get("error_type") == "RuntimeError" for e in events)
    assert all(e["request_id"] == response.headers["X-Request-ID"] for e in events)


def test_xss_sql_are_data(client):
    text = "<script>alert(1)</script>' OR 1=1; DROP TABLE users; --"
    response = client.post("/", data={"check_type": "email", "email_text": text})
    assert response.status_code == 405
    response = client.post("/api/v1/scan", json={"url": "https://example.com/?q=%27OR%201=1--"})
    assert response.status_code == 200


def test_dns_mixed_addresses_rejected(monkeypatch):
    monkeypatch.setattr(outbound.dns.resolver, "resolve", lambda *a, **kw: ["8.8.8.8", "127.0.0.1"])
    with pytest.raises(InvalidURL):
        outbound.resolve_public("example.com")


def test_head_pins_ip_preserves_tls_and_never_redirects(monkeypatch):
    monkeypatch.setattr(outbound, "resolve_public", lambda host: ["8.8.8.8"])
    factory = Mock()
    pool = factory.return_value
    pool.urlopen.return_value.status = 302
    monkeypatch.setattr(outbound.urllib3, "HTTPSConnectionPool", factory)
    assert outbound.safe_head("https://example.com/path?q=1")
    assert factory.call_args.kwargs["host"] == "8.8.8.8"
    assert factory.call_args.kwargs["server_hostname"] == "example.com"
    assert factory.call_args.kwargs["assert_hostname"] == "example.com"
    args = pool.urlopen.call_args
    assert args.kwargs["redirect"] is False and args.kwargs["retries"] is False
    assert args.kwargs["headers"]["Host"] == "example.com"
    assert args.kwargs["preload_content"] is False
    pool.close.assert_called_once()


def test_private_dns_blocks_before_connection(monkeypatch):
    monkeypatch.setattr(outbound.dns.resolver, "resolve", lambda *a, **kw: ["169.254.169.254"])
    pool = Mock()
    monkeypatch.setattr(outbound.urllib3, "HTTPConnectionPool", pool)
    with pytest.raises(InvalidURL):
        outbound.safe_head("http://example.com")
    pool.assert_not_called()


@pytest.mark.parametrize("overrides", [{"SECRET_KEY": None}, {"SECRET_KEY": "dev-secret-key"},
    {"SITE_URL": "http://example.com"}, {"ALLOWED_ORIGINS": ["*"]}, {"RATELIMIT_STORAGE_URI": "memory://"},
    {"MAX_CONCURRENT_SCANS": 0}, {"TRUSTED_HOSTS": ["*"]}, {"SCAN_RATE_LIMIT": "unlimited"},
    {"SCAN_RATE_LIMIT": "0 per minute"}, {"RATELIMIT_STORAGE_URI": "memory://another"}])
def test_production_config_fails_closed(overrides):
    config = {"APP_ENV": "production", "SECRET_KEY": "a" * 48, "SITE_URL": "https://example.com",
              "ALLOWED_ORIGINS": [], "TRUSTED_HOSTS": ["example.com"], "RATELIMIT_STORAGE_URI": "redis://localhost:6379"}
    config.update(overrides)
    with pytest.raises(ValueError):
        create_app(config)


def test_model_regression(app):
    from utils.url_features import extract_advanced_url_features
    predictor = app.extensions["ml_predictor"]
    for domain in ("google.com", "github.com", "microsoft.com", "wikipedia.org", "amazon.in"):
        plain = predictor.predict(extract_advanced_url_features("https://" + domain), include_explanations=False)
        www = predictor.predict(extract_advanced_url_features("https://www." + domain), include_explanations=False)
        assert plain["status"] == www["status"] == "OK"
        assert plain["probability"] == www["probability"]
        assert plain["prediction"] == "legitimate"
