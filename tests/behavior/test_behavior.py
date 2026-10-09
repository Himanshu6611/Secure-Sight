import copy
import json
import pytest
from app.behavior.analyzer import analyze_behavior
from app.behavior.config import load_config, validate_config
from app.behavior.evidence import validate_behavior
from app.explanations.engine import ExplanationEngine
from app.risk.engine import RiskScoringEngine
from utils.web_intelligence import analyze_web_intelligence
from utils.dynamic_analysis import analyze_webpage_dynamically
from tests.explanation.test_engine import observations
from tests.redirect.test_redirects import transport
from utils import safe_fetch


@pytest.mark.parametrize("snippet,code", [
    ('<meta http-equiv="refresh" content="0;url=https://example.net/reset?token=SECRET">','BEHAVIOR_META_REFRESH'),
    ('<script>location.href="https://example.net/"</script>','BEHAVIOR_JAVASCRIPT_REDIRECT'),
    ('<script>location.replace("https://example.net/")</script>','BEHAVIOR_JAVASCRIPT_REDIRECT'),
    ('<script>window.location="https://example.net/"</script>','BEHAVIOR_JAVASCRIPT_REDIRECT'),
    ('<script>window.location.href="https://example.net/"</script>','BEHAVIOR_JAVASCRIPT_REDIRECT'),
    ('<script>eval(atob("AAAA"))</script>','BEHAVIOR_OBFUSCATED_SCRIPT'),
    ('<script>window.open("/new")</script>','BEHAVIOR_NEW_WINDOW_PATTERN'),
    ('<div class="g-recaptcha">Challenge</div>','BEHAVIOR_CHALLENGE_PATTERN')])
def test_actual_static_patterns_no_execution(snippet, code):
    web = analyze_web_intelligence("https://example.com/", snippet)
    behavior = web["behavior_intelligence"]
    assert code in {r["indicator"] for r in behavior["indicators"]}
    assert behavior["dynamic_analysis"]["status"] == "NOT_RUN"
    assert "SECRET" not in json.dumps(behavior)
    assert not any(d["executed"] for d in behavior["static_behavior"]["destinations"])


def test_static_destinations_blocked_and_delayed_observation():
    web = analyze_web_intelligence("https://example.com/", '<meta http-equiv="refresh" content="3.5;url=http://127.0.0.1/">')
    behavior = web["behavior_intelligence"]
    assert behavior["static_behavior"]["destinations"][0]["delay_seconds"] == 3.5
    assert any(r["indicator"] == "BEHAVIOR_STATIC_DESTINATION_BLOCKED" for r in behavior["indicators"])
    assert "127.0.0.1" not in json.dumps(behavior)


def test_static_resource_limit_and_json_script_exclusion():
    web = analyze_web_intelligence("https://example.com/", '<script type="application/ld+json">location.href="https://example.net/"</script>' +
        '<script>' + 'location.href="https://example.net/";'*100 + '</script>')
    static = web["behavior_intelligence"]["static_behavior"]
    assert len(static["destinations"]) == load_config()["max_static_destinations"]
    assert static["destination_limit_reached"] is True


def behavior_context(monkeypatch, target="https://example.net/", loop=False):
    ctx = observations(False, .02, "SAFE")
    routes = {"https://example.com/":{"status":302,"location":target}, target:{}}
    if loop:
        routes[target] = {"status":302,"location":"https://example.com/"}
    transport(monkeypatch, routes)
    fetch = safe_fetch.fetch_webpage_safely("https://example.com/")
    ctx["behavior_intelligence"] = analyze_behavior("https://example.com/", fetch, {"status":"ANALYZED","destinations":[]})
    return ctx


def test_ordinary_cross_domain_no_points_or_automatic_phishing(monkeypatch):
    ctx = behavior_context(monkeypatch)
    engine = RiskScoringEngine()
    baseline = engine.calculate({key:value for key,value in ctx.items() if key != "behavior_intelligence"})
    result = engine.calculate(ctx)
    assert result["risk_score"] == baseline["risk_score"]
    assert result["verdict"] == "LEGITIMATE"
    assert result["behavioral_evidence"]
    explanation = ExplanationEngine().explain(result, ctx["ml_result"], ctx["web_intelligence"])
    assert any(r["reason_id"] == "BEHAVIOR_CROSS_DOMAIN" for r in explanation["behavioral_reasons"])
    assert all(r["score_contribution"] == 0 for r in explanation["behavioral_reasons"])


def test_downgrade_adjustment_centralized_and_bounded(monkeypatch):
    ctx = behavior_context(monkeypatch, target="http://example.net/")
    engine = RiskScoringEngine()
    original = engine.calculate({key:value for key,value in ctx.items() if key != "behavior_intelligence"})
    result = engine.calculate(ctx)
    assert result["risk_score"] == pytest.approx(original["risk_score"]+engine.config["behavior"]["indicator_points"]["BEHAVIOR_HTTPS_TO_HTTP"], abs=1e-4)
    assert result["verdict"] != "PHISHING"
    assert sum(r["score_contribution"] for r in result["behavioral_evidence"]) <= 10


def test_failure_and_loop_never_legitimate(monkeypatch):
    ctx = behavior_context(monkeypatch, loop=True)
    assessment = RiskScoringEngine().calculate(ctx)
    assert assessment["verdict"] == "UNKNOWN"
    assert assessment["behavior_status"] == "REDIRECT_LOOP"
    explanation = ExplanationEngine().explain(assessment)
    assert any(r["reason_id"] == "BEHAVIOR_REDIRECT_LOOP" for r in explanation["behavioral_reasons"])
    assert any(r["signal_id"] == "BEHAVIOR_ANALYSIS" for r in explanation["missing_information"])


def test_unexecuted_client_navigation_blocks_definitive_safe():
    ctx = observations(False, .02, "SAFE")
    ctx["web_intelligence"] = analyze_web_intelligence("https://example.com/", '<meta http-equiv="refresh" content="0;url=https://example.net/">')
    ctx["behavior_intelligence"] = ctx["web_intelligence"]["behavior_intelligence"]
    result = RiskScoringEngine().calculate(ctx)
    assert result["verdict"] == "UNKNOWN"
    assert any(w["code"] == "CLIENT_NAVIGATION_UNOBSERVED" for w in result["warnings"])


def test_destination_correlation_uses_existing_model_provenance(monkeypatch):
    ctx = behavior_context(monkeypatch)
    ctx["ml_result"]["probability"] = .99
    result = RiskScoringEngine().calculate(ctx)
    assert any(r["indicator"] == "BEHAVIOR_SUSPICIOUS_FINAL_DESTINATION" for r in result["behavioral_evidence"])
    assert result["independent_risk_sources"] == ["URL_MODEL"]
    assert result["verdict"] != "PHISHING"


def test_chain_deduplication_no_extra_risk(monkeypatch):
    ctx = behavior_context(monkeypatch, "http://example.net/")
    engine = RiskScoringEngine()
    first = engine.calculate(ctx)
    ctx["behavior_intelligence"]["indicators"] *= 2
    repeated = engine.calculate(ctx)
    assert repeated["risk_score"] == first["risk_score"]


@pytest.mark.parametrize("field,value", [("dynamic_enabled",True), ("max_redirects",1000),
    ("max_response_size_bytes",10000000), ("total_timeout_seconds",float("inf")), ("sensitive_query_keys",["<script>"])])
def test_configuration_rejects_unsafe_or_unbounded(field, value):
    config = load_config()
    config[field] = value
    with pytest.raises(ValueError):
        validate_config(config)


def test_browser_disabled_even_when_requested():
    result = analyze_webpage_dynamically("https://example.com/", allow_headless=True)
    assert result["status"] == "DYNAMIC_ANALYSIS_UNAVAILABLE"
    assert result["security_enforcement"]["javascript_executed"] is False
    assert result["security_enforcement"]["forms_submitted"] is False
    assert result["request_count"] == 0


def test_behavior_schema_mismatch_fails_closed(monkeypatch):
    ctx = behavior_context(monkeypatch)
    ctx["behavior_intelligence"]["feature_version"] = "5.1.1"
    assessment = RiskScoringEngine().calculate(ctx)
    assert assessment["verdict"] == "ANALYSIS_FAILED"


def test_final_destination_pipeline_and_private_internal_field_removed(client, monkeypatch):
    from app.services import scans
    ctx = observations(False, .02, "SAFE")
    transport(monkeypatch, {"https://example.com/":{"status":302,"location":"https://example.net/login?token=SECRET"},
        "https://example.net/login?token=SECRET":{"body":b'<title>SECRET</title><form><input type="password"></form><a href="?token=SECRET">Link</a>'}})
    calls = []
    def domain(url):
        calls.append(url)
        return copy.deepcopy(ctx["domain_intelligence"])
    monkeypatch.setattr(scans, "analyze_domain_intelligence", domain)
    result = client.post("/api/v1/scan", json={"url":"https://example.com/"})
    assert result.status_code == 200
    body = result.json
    assert body["behavior_intelligence"]["final_destination_reached"] is True
    assert len(calls) == 2
    assert body["advanced_analysis"]["features"]["hostname_len"] == len("example.net")
    assert body["analysis_target"].startswith("https://example.net/")
    assert "SECRET" not in json.dumps(body)
    assert "_analysis_target" not in body["web_intelligence"]
    assert body["feature_schema_version"] == "5.1.1"
    assert len(body["feature_vector"]) == 97
    assert any(r["reason_id"] == "BEHAVIOR_FINAL_DOMAIN_CHANGE" for r in body["explanation"]["behavioral_reasons"])


def test_behavior_is_deterministic_and_non_mutating(monkeypatch):
    ctx = behavior_context(monkeypatch)
    before = copy.deepcopy(ctx)
    engine = RiskScoringEngine()
    first = engine.calculate(ctx)
    assert engine.calculate(ctx) == first
    assert ctx == before


def test_public_web_endpoint_redacts_queries(client, monkeypatch):
    transport(monkeypatch, {"https://example.com/login?code=SECRET": {
        "body":b'<title>SECRET</title><form action="?code=SECRET"><input type="password"></form>'}})
    response = client.post("/api/v1/analyze/webpage", json={"url":"https://example.com/login?code=SECRET"})
    assert response.status_code == 200
    assert "SECRET" not in response.get_data(as_text=True)
    assert "_analysis_target" not in response.json["web_intelligence"]


def test_behavior_indicators_cannot_invent_observations(monkeypatch):
    ctx = behavior_context(monkeypatch)
    record = next(r for r in ctx["behavior_intelligence"]["indicators"] if r["indicator"] == "BEHAVIOR_CROSS_DOMAIN")
    ctx["behavior_intelligence"]["features"]["domain_transition_count"] = 0
    assert record["value"] > 0
    assert RiskScoringEngine().calculate(ctx)["verdict"] == "ANALYSIS_FAILED"


def test_behavior_feature_registry_is_separate_from_model():
    from pathlib import Path
    from ml.features import FEATURE_ORDER
    from app.behavior.evidence import FEATURES
    registry = json.loads(Path("config/behavior_features.json").read_text())
    assert registry["feature_schema_version"] == "8.0.0"
    assert registry["used_by_serving_model"] is False
    assert set(registry["features"]) == FEATURES
    assert not set(FEATURE_ORDER).intersection(FEATURES)


def test_behavior_logs_have_only_safe_fields(client, monkeypatch):
    from app.services import scans
    from app.core.observability import JSONFormatter
    import logging
    ctx = observations(False, .02, "SAFE")
    transport(monkeypatch, {"https://example.com/?token=SECRET":{}})
    monkeypatch.setattr(scans, "analyze_domain_intelligence", lambda url:ctx["domain_intelligence"])
    records = []
    class Handler(logging.Handler):
        def emit(self, record):
            records.append(record)
    client.application.logger.addHandler(Handler())
    response = client.post("/api/v1/scan",json={"url":"https://example.com/?token=SECRET"})
    assert response.status_code == 200
    event = next(r for r in records if r.getMessage() == "redirect_analysis_completed")
    event.url = "https://example.com/?token=SECRET"
    serialized = JSONFormatter().format(event)
    assert "SECRET" not in serialized
    assert '"phase": "8"' in serialized
