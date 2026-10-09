"""Local security regressions for verified Phase 13 fixes; no external targets."""
import io
import json
import logging
from pathlib import Path
import subprocess
import time
from unittest.mock import Mock
import pytest
from app import create_app
from app.security.json_policy import strict_loads
from app.security.circuit import ProviderCircuit, ProviderUnavailable
from app.security import outbound, json_fetch
from app.security.urls import InvalidURL
from tests.test_phase12_dashboard import accounts, authenticate, saved, url_result
from tests.test_phase10_media import image_bytes


@pytest.mark.parametrize("payload", [
    '{"url":"https://example.com","url":"http://127.0.0.1"}',
    '{"features":{"x":NaN}}', '{"features":{"x":Infinity}}',
    '{"features":{"x":1e999}}', '{"x":' + '[' * 40 + '0' + ']' * 40 + '}',
    '{"x":[' + ','.join('0' for _ in range(1025)) + ']}',
])
def test_json_rejected_before_detector(client, app, monkeypatch, payload):
    call = Mock(side_effect=AssertionError("Expensive work must not run"))
    monkeypatch.setattr("app.api.v1.scan_url", call)
    response = client.post("/api/v1/scan", data=payload, content_type="application/json")
    assert response.status_code == 400 and response.json["error"]["code"] == "INVALID_INPUT"
    assert response.json["request_id"] == response.headers["X-Request-ID"]
    call.assert_not_called()
    assert app.extensions["scan_slots"].acquire(False)
    app.extensions["scan_slots"].release()


def test_json_quoted_brackets_and_unicode_are_data():
    value = {"text": 'हिंदी ' + '[' * 40 + '\\"' + ']' * 40}
    assert strict_loads(json.dumps(value).encode()) == value


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_authorization_precedes_busy_capacity(client, app, accounts, role):
    authenticate(client, accounts[role])
    slots = app.extensions["scan_slots"]
    for _ in range(app.config["MAX_CONCURRENT_SCANS"]):
        assert slots.acquire(False)
    try:
        assert client.post("/api/v1/scan", json={"url": "https://example.com"}).status_code == 403
        # Private case writes do not reserve unrelated detector capacity.
        response = client.post("/api/v1/cases", json={"title": "Local case"}, headers={"X-CSRF-Token": "test-csrf-token"})
        assert response.status_code == (403 if role == "viewer" else 201)
    finally:
        for _ in range(app.config["MAX_CONCURRENT_SCANS"]):
            slots.release()


def test_unicode_csrf_and_bad_bearer_fail_closed(client, accounts):
    authenticate(client, accounts["analyst"])
    assert client.post("/api/v1/cases", json={}, headers={"X-CSRF-Token": "हिंदी"}).status_code == 403
    for token in ("wrong", "x" * 10000, "हिंदी"):
        response = client.get("/api/v1/investigations", headers={"Authorization": "Bearer " + token})
        assert response.status_code == 401  # No cookie fallback.


@pytest.mark.parametrize("extra", [{"tenant": "team-b"}, {"role": "ADMIN"}, {"verdict": "LEGITIMATE"}, {"risk_score": 0}])
def test_private_mass_assignment(client, accounts, extra):
    headers = authenticate(client, accounts["analyst"])
    response = client.post("/api/v1/cases", json={"title": "Case", **extra}, headers=headers)
    assert response.status_code == 400


def test_cors_and_error_contract(client, app):
    app.config["ALLOWED_ORIGINS"] = ["https://allowed.example"]
    response = client.options("/api/v1/cases", headers={"Origin": "https://allowed.example", "Access-Control-Request-Headers": "Authorization"})
    assert response.headers["Access-Control-Allow-Origin"] == "https://allowed.example"
    assert "Access-Control-Allow-Credentials" not in response.headers
    assert "Authorization" not in response.headers["Access-Control-Allow-Headers"]
    assert client.post("/api/v1/cases", json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    response = client.get("/api/v1/cases")
    assert response.status_code == 401 and response.json["error"]["code"] == "UNAUTHORIZED"


def test_actor_and_failure_logging_are_content_free(client, app, accounts, monkeypatch):
    headers = authenticate(client, accounts["analyst"])
    def failed(value):
        raise RuntimeError("SECRET_TOKEN raw email body")
    monkeypatch.setattr("app.api.v1.scan_url", failed)
    log = io.StringIO()
    handler, original = app.logger.handlers[0], app.logger.handlers[0].stream
    handler.setStream(log)
    try:
        response = client.post("/api/v1/scan", json={"url": "https://example.com/?token=SECRET_TOKEN"}, headers=headers)
    finally:
        handler.setStream(original)
    assert response.status_code == 500
    assert "SECRET_TOKEN" not in response.get_data(as_text=True) + log.getvalue()
    events = [json.loads(line) for line in log.getvalue().splitlines()]
    assert events[-1]["actor_id"] == accounts["analyst"]["id"]
    assert events[-1]["error_code"] == "INTERNAL_ERROR"


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "::1", "fe80::1", "224.0.0.1", "100.64.0.1"])
def test_provider_redirect_blocks_private_before_second_socket(monkeypatch, host):
    address = '[' + host + ']' if ':' in host else host
    response = Mock(status=302, headers={"Location": "https://" + address})
    pool = Mock(); pool.urlopen.return_value = response
    gateway = Mock(return_value=(outbound.urlsplit("https://provider.example/data"), pool))
    monkeypatch.setattr(json_fetch, "pinned_pool", gateway)
    with pytest.raises(InvalidURL):
        json_fetch.fetch_json("https://provider.example/data", time.monotonic() + 2)
    assert gateway.call_count == 1
    response.close.assert_called_once(); pool.close.assert_called_once()


def test_pinned_gateway_rechecks_every_answer_and_does_not_reresolve(monkeypatch):
    resolver = Mock(side_effect=[["8.8.8.8"], ["127.0.0.1"]])
    monkeypatch.setattr(outbound, "resolve_public", resolver)
    factory = Mock()
    monkeypatch.setattr(outbound.urllib3, "HTTPSConnectionPool", factory)
    _, pool = outbound.pinned_pool("https://example.com")
    assert factory.call_args.kwargs["host"] == "8.8.8.8" and resolver.call_count == 1
    pool.close()
    with pytest.raises(InvalidURL):
        outbound.pinned_pool("https://example.com")
    assert factory.call_count == 1


@pytest.mark.parametrize("raw", [b'{"status":"ok","status":"SAFE"}', b'{"risk":NaN}', b'{"x":1e999}', b'{"x":' + b'[' * 24 + b'0' + b']' * 24 + b'}'])
def test_poisoned_provider_json_is_rejected(monkeypatch, raw):
    response = Mock(status=200, headers={"Content-Type": "application/json"})
    response.read1.side_effect = [raw, b'']
    pool = Mock(); pool.urlopen.return_value = response
    monkeypatch.setattr(json_fetch, "pinned_pool", lambda *a, **k: (outbound.urlsplit("https://provider.example/data"), pool))
    with pytest.raises(ValueError):
        json_fetch.fetch_json("https://provider.example/data", time.monotonic() + 2)
    response.close.assert_called_once(); pool.close.assert_called_once()


def test_provider_circuit_opens_recovers_and_bounds_memory(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr("app.security.circuit.time.monotonic", lambda: clock[0])
    circuit = ProviderCircuit(failures=2, cooldown=10, max_entries=2)
    for _ in range(2):
        with pytest.raises(OSError), circuit.attempt("https://provider.example/?token=PRIVATE"):
            raise OSError("Provider unavailable")
    with pytest.raises(ProviderUnavailable), circuit.attempt("https://provider.example/another"):
        pytest.fail("Circuit must block network work")
    assert "PRIVATE" not in repr(circuit.entries)
    clock[0] = 21
    with circuit.attempt("https://provider.example"):
        with pytest.raises(ProviderUnavailable), circuit.attempt("https://provider.example"):
            pytest.fail("Only one recovery probe allowed")
    with circuit.attempt("https://provider.example"):
        pass
    for host in ("one.example", "two.example", "three.example"):
        with circuit.attempt("https://" + host):
            pass
    assert len(circuit.entries) == 2


@pytest.mark.parametrize("name", ["image.exe", "image.svg", "image.jpg", "image"])
def test_upload_extension_magic_mismatch_before_decoder(client, monkeypatch, name):
    decoder = Mock(side_effect=AssertionError("Decoder must not run"))
    monkeypatch.setattr("app.media.service.run", decoder)
    response = client.post("/api/v1/media/analyze", data={"file": (io.BytesIO(image_bytes()), name, "image/png")})
    assert response.status_code == 415 and response.json["verdict"] == "UNKNOWN"
    decoder.assert_not_called()


def test_worker_env_workspace_cleanup_and_no_persistence(monkeypatch):
    from app.media import worker
    monkeypatch.setenv("FLASK_SECRET_KEY", "PRIVATE_SERVICE_SECRET")
    monkeypatch.setenv("DASHBOARD_ENCRYPTION_KEY", "PRIVATE_DASHBOARD_SECRET")
    monkeypatch.setenv("HTTP_PROXY", "http://private.proxy")
    real = subprocess.Popen
    seen = {}
    def inspect_process(args, **kwargs):
        seen.update(kwargs)
        return real([worker.sys.executable, "-c", "import json,os; print(json.dumps({'cwd':os.getcwd(),'tmp':os.environ['TMP'],'secret':os.environ.get('FLASK_SECRET_KEY')}))"], **kwargs)
    monkeypatch.setattr(worker.subprocess, "Popen", inspect_process)
    result = worker.run(b"local fixture", {"mime": "--url"}, "eng")
    assert result["secret"] is None and result["cwd"] == result["tmp"]
    assert not Path(result["cwd"]).exists()
    assert not {"FLASK_SECRET_KEY", "DASHBOARD_ENCRYPTION_KEY", "HTTP_PROXY"} & set(seen["env"])


def test_linked_worker_configuration_contains_no_service_secrets(monkeypatch):
    from app.media import worker
    call = Mock(return_value={"status": "PARTIAL"})
    monkeypatch.setattr(worker, "run", call)
    worker.run_linked("https://example.com", None, {"APP_ENV": "production", "SECRET_KEY": "PRIVATE"})
    payload = json.loads(call.call_args.args[0])
    assert payload["config"]["ANALYSIS_WORKER"] is True
    assert payload["config"]["RATELIMIT_STORAGE_URI"] == "memory://"
    assert "PRIVATE" not in repr(payload)


def test_analysis_factory_never_reads_dotenv_or_creates_private_store(monkeypatch):
    read_env = Mock(side_effect=AssertionError("No dotenv in scanner children"))
    monkeypatch.setattr("app.load_dotenv", read_env)
    application = create_app({"APP_ENV": "testing", "ANALYSIS_WORKER": True, "RATELIMIT_STORAGE_URI": "memory://"})
    assert "dashboard_store" not in application.extensions
    assert not any(rule.rule.startswith("/dashboard") for rule in application.url_map.iter_rules())
    read_env.assert_not_called()


def test_worker_start_failure_cleans_private_workspace(monkeypatch):
    from app.media import worker
    seen = {}
    def failed(*args, **kwargs):
        seen.update(kwargs)
        raise OSError("private process details")
    monkeypatch.setattr(worker.subprocess, "Popen", failed)
    with pytest.raises(worker.MediaError, match="ANALYSIS_FAILED"):
        worker.run(b"fixture", {"mime": "--url"}, "eng")
    assert not Path(seen["cwd"]).exists()


def test_whois_header_command_injection_blocked(monkeypatch):
    connect = Mock(side_effect=AssertionError("No socket"))
    monkeypatch.setattr(outbound.socket, "create_connection", connect)
    for value in ("example.com\r\nOTHER", "example.com/path", "example.com?query=test"):
        with pytest.raises(InvalidURL):
            outbound.whois_text(value)
    connect.assert_not_called()


def test_docker_excludes_private_runtime_files():
    policy = (Path(__file__).resolve().parents[1] / ".dockerignore").read_text()
    assert all(value in policy.splitlines() for value in ("instance", "app/instance", "**/*.sqlite3", "**/dashboard.key", "**/dashboard-login.txt"))


def test_query_budget(client):
    assert client.get("/api/v1/health?x=" + "a" * 4100).status_code == 400


def test_boolean_resource_configuration_rejected():
    with pytest.raises(ValueError, match="positive integer"):
        create_app({"APP_ENV": "testing", "MAX_CONCURRENT_SCANS": True})


def test_actor_endpoint_limit_and_retry_do_not_leak_credentials(client, app, accounts, monkeypatch):
    app.config["ACTOR_SCAN_RATE_LIMIT"] = "2 per minute"
    headers = authenticate(client, accounts["analyst"])
    monkeypatch.setattr("app.api.v1.scan_url", lambda *a: {"status": "PARTIAL", "assessment": {"verdict": "UNKNOWN"}})
    for _ in range(2):
        assert client.post("/api/v1/scan", json={"url": "https://example.com"}, headers=headers).status_code == 200
    response = client.post("/api/v1/scan", json={"url": "https://example.com"}, headers=headers)
    assert response.status_code == 429 and response.headers["Retry-After"]
    assert response.json["error"]["code"] == "RATE_LIMITED"
    other = app.test_client(); other_headers = authenticate(other, accounts["other"])
    assert other.post("/api/v1/scan", json={"url": "https://example.com"}, headers=other_headers).status_code == 200


def test_access_log_suppressed_and_secret_scanner_detects_without_values(app):
    from scripts.security_inventory import scan_source
    assert logging.getLogger("werkzeug").level >= logging.WARNING
    secret = "literal-private-password"
    findings = scan_source("sample.py", 'password = "' + secret + '"')
    assert findings and findings[0]["category"] == "LITERAL_CREDENTIAL_REVIEW"
    assert secret not in json.dumps(findings)


@pytest.mark.parametrize("stage", ["reputation", "registration", "html", "ml"])
def test_partial_intelligence_never_authorizes_legitimate(app, stage):
    from tests.risk.test_engine import context
    import copy
    complete = context()
    original = copy.deepcopy(complete)
    engine = app.extensions["risk_engine"]
    assert engine.calculate(complete)["verdict"] == "LEGITIMATE"
    if stage == "html":
        complete["web_intelligence"]["status"] = "ANALYSIS_FAILED"
    elif stage == "ml":
        complete["ml_result"]["status"] = "MODEL_NOT_FOUND"
    elif stage == "reputation":
        complete["domain_intelligence"][stage] = {"reputation_status": "UNKNOWN"}
    else:
        complete["domain_intelligence"][stage] = {"status": "UNAVAILABLE"}
    before = copy.deepcopy(complete)
    result = engine.calculate(complete)
    assert result["verdict"] not in {"LEGITIMATE", "SAFE"}
    assert any(w["code"] == "SAFETY_WITHHELD_PARTIAL" for w in result["warnings"])
    assert complete == before and original != complete
