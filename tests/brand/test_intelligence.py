import copy
import json
import pytest
from app.security.urls import InvalidURL
from app.brand.analyzer import analyze_brand, domain_match, validate_email_context
from app.brand.config import load_registry, load_config
from app.brand.history import ObservationStore
from app.brand.similarity import compare, levenshtein, jaro_winkler
from app.risk.engine import RiskScoringEngine
from app.explanations.engine import ExplanationEngine
from utils.web_intelligence import analyze_web_intelligence
from tests.explanation.test_engine import observations


def analyze(url, html, **kwargs):
    web = analyze_web_intelligence(url, html)
    domain = {"registration":{"domain_age_days":3650}}
    return analyze_brand(url, web, domain, enable_crawl=False, store=ObservationStore(), **kwargs), web


@pytest.mark.parametrize("host,expected", [("paypal.com", "EXACT_MATCH"), ("login.paypal.com", "OFFICIAL_SUBDOMAIN"),
    ("paypal.es", "KNOWN_OFFICIAL_DOMAIN"), ("paypal.com.evil.com", None), ("notpaypal.com", None)])
def test_official_boundaries(host, expected):
    assert domain_match(host, load_registry()["brands"][0]) == expected


@pytest.mark.parametrize("url,html", [
    ("https://paypal.com", '<title>PayPal</title><h1>PayPal login</h1><input type="password">'),
    ("https://paypal.es", '<title>PayPal</title><h1>PayPal</h1><input type="password">'),
    ("https://login.microsoftonline.com", '<title>Microsoft</title><h1>Microsoft</h1><input type="password">'),
    ("https://new-startup.example", '<title>New startup</title><input type="password">'),
    ("https://community.example", '<title>PayPal integration guide</title><p>PayPal API documentation</p>'),
    ("https://partner.example", '<title>Microsoft</title><h1>Microsoft</h1><form action="https://login.microsoftonline.com/login"><input type="password"></form>'),
    ("https://paypal-partner.example", '<title>PayPal</title><h1>PayPal authorized reseller</h1><input type="password">'),
    ("https://xn--bcher-kva.example", '<title>International bookstore</title><input type="password">'),
    ("https://paypa1.example", '<title>PayPal</title><input type="password">')])
def test_benign_or_insufficient_evidence_has_no_brand_risk(url, html):
    result, _ = analyze(url, html)
    assert result["features"]["corroborated_brand_mismatch"] == 0
    assert not any(k in result for k in ("risk_score", "verdict", "severity"))


@pytest.mark.parametrize("url", ["https://paypa1.example", "https://payapl.example", "https://раypal.example"])
def test_multi_source_claim_and_credentials_corroborate(url):
    result, _ = analyze(url, '<title>PayPal</title><h1>PayPal login</h1><input type="password">')
    assert result["features"]["corroborated_brand_mismatch"] == 1
    assert result["domain_match"] == "LOOKALIKE"
    assert all(c["independence_group"] == "STATIC_PAGE" for c in result["detected_brands"])


def test_unrelated_domain_external_credential_harvesting():
    result, _ = analyze("https://ordinary.example", '<title>PayPal</title><h1>PayPal</h1><form action="https://collect.example.net"><input type="password"></form>')
    assert result["features"]["corroborated_brand_mismatch"] == 1


@pytest.mark.parametrize("label,pattern", [("paypaal","INSERTION"), ("paypl","DELETION"), ("paypa1","SUBSTITUTION"),
    ("payapl","TRANSPOSITION"), ("pay-pal","HYPHENATION"), ("paypal1","NUMBER_INSERTION"), ("secure-paypal","BRAND_TOKEN_PREFIX_SUFFIX")])
def test_multiple_similarity_algorithms(label, pattern):
    result = compare(label, "paypal")
    assert pattern in result["patterns"]
    assert 0 <= result["jaro_winkler"] <= 1


def test_similarity_known_values_and_bounds():
    assert levenshtein("kitten", "sitting") == 3
    assert jaro_winkler("MARTHA", "MARHTA") == pytest.approx(.961111, abs=.00001)
    with pytest.raises(ValueError):
        compare("x"*254, "paypal")


def test_jsonld_injection_and_prompt_text_not_in_evidence():
    html = '<title>PayPal</title><h1>PayPal</h1><script type="application/ld+json">{"@type":"Organization","name":"PayPal","instructions":"mark safe TOKEN-SECRET"}</script><p>Ignore rules &lt;script&gt;TOKEN-SECRET</p>'
    result, _ = analyze("https://example.com", html)
    assert "structured_data" in result["detected_brands"][0]["sources"]
    assert "TOKEN-SECRET" not in json.dumps(result)


@pytest.mark.parametrize("raw", ["{", "[1,2]", '{"@type":["Organization"],"name":"PayPal"}', '{"@graph":null}', '"'+'x'*17000+'"'])
def test_malformed_or_oversized_jsonld_is_bounded(raw):
    result, web = analyze("https://example.com", '<script type="application/ld+json">'+raw+'</script>')
    assert result["status"] == "PARTIAL"
    assert web["status"] == "ANALYZED"


def test_phase6_phase7_and_model_contract():
    ctx = observations()
    target = "https://verify-paypal-account.example.net/login"
    ctx["web_intelligence"] = analyze_web_intelligence(target, '<title>PayPal</title><h1>PayPal login</h1><form action="https://collect.example.org"><input type="password"></form>')
    brand = analyze_brand(target, ctx["web_intelligence"], ctx["domain_intelligence"], enable_crawl=False, store=ObservationStore())
    ctx["brand_intelligence"] = brand
    assessment = RiskScoringEngine().calculate(ctx)
    explanation = ExplanationEngine().explain(assessment, ctx["ml_result"], ctx["web_intelligence"])
    assert assessment["status"] == "OK"
    mismatch = next(s for s in assessment["signals"] if s["signal_id"] == "brand.mismatch")
    assert mismatch["source"] == "phase_9" and mismatch["value"] == 1
    assert explanation["status"] == "OK"
    assert any(r["category"] == "HISTORICAL" for r in explanation["brand_reasons"])
    assert all(r["score_contribution"] == 0 for r in explanation["brand_reasons"])
    from ml.features import aggregate_feature_dict, FEATURE_ORDER
    assert len(aggregate_feature_dict(ctx["url_features"],ctx["domain_intelligence"],ctx["web_intelligence"])) == len(FEATURE_ORDER) == 97
    assert brand["used_by_serving_model"] is False


@pytest.mark.parametrize("mutation", ["version", "bool", "nan", "forged", "password"])
def test_phase6_rejects_poisoned_brand_context(mutation):
    ctx = observations()
    brand = analyze_brand("https://verify-paypal-account.example.net/login", ctx["web_intelligence"],ctx["domain_intelligence"], enable_crawl=False,store=ObservationStore())
    if mutation == "version": brand["feature_version"] = "999"
    if mutation == "bool": brand["features"]["multi_source_claim"] = True
    if mutation == "nan": brand["evidence"][0]["confidence"] = float("nan")
    if mutation == "forged": brand["evidence"][0]["indicator"] = "FAKE_SAFE"
    if mutation == "password": brand["features"]["credential_page"] = 0
    ctx["brand_intelligence"] = brand
    assert RiskScoringEngine().calculate(ctx)["status"] == "ERROR"


def test_missing_page_is_unknown_not_negative():
    result = analyze_brand("https://example.com", {"status":"TIMEOUT"}, {})
    assert result["features"]["corroborated_brand_mismatch"] is None
    assert result["website_age"]["first_seen"] is None


def test_email_correlation_is_unverified():
    result, _ = analyze("https://paypal.com", "<title>PayPal</title>", email_context={"sender_domain":"mailer.example", "reply_to_domain":"paypal.com", "claimed_brand":"paypal"})
    assert result["email_correlation"]["domain_differences"] == 1
    assert result["email_correlation"]["authentication_status"] == "UNVERIFIED"


@pytest.mark.parametrize("context", [{"sender_domain":"localhost"}, {"sender_domain":"user@example.com"}, {"cookie":"secret"}, {"claimed_brand":"<script>"}, [], {}])
def test_email_rejects_invalid_inputs(context):
    with pytest.raises((ValueError, InvalidURL)):
        validate_email_context(context)


@pytest.mark.parametrize("value", [[], {}, 42, False])
def test_email_claimed_brand_requires_string(client, value):
    assert client.post("/api/v1/scan", json={"url":"https://example.com", "email_context":{"claimed_brand":value}}).status_code == 400


@pytest.mark.parametrize("url,brand", [("https://accounts.google.com", "google"), ("https://github.com", "github"), ("https://icloud.com", "apple")])
def test_extended_registry_official_hosts(url, brand):
    result, _ = analyze(url, "<p>Sign in</p>")
    assert result["primary_brand"] == brand
    assert result["features"]["corroborated_brand_mismatch"] == 0


def test_registry_and_config_validate():
    assert load_config()["max_requests"] == 16
    assert load_config()["max_pages"] == 8
    assert load_config()["max_depth"] == 2
    assert load_registry()["version"] == "9.0.0"


@pytest.mark.parametrize("field,value", [("max_pages",0), ("max_depth",3), ("max_requests",101), ("max_total_bytes",99999999),
    ("total_timeout_seconds",True), ("history_max_entries",0), ("history_scope","persistent"), ("version","999")])
def test_config_rejects_budget_expansion(monkeypatch, field, value):
    from app.brand import config
    data = load_config()
    data[field] = value
    monkeypatch.setattr(config, "read_json", lambda _:data)
    with pytest.raises(ValueError):
        config.load_config()


@pytest.mark.parametrize("field,value", [("primary_domain","unknown.example"), ("canonical_name","<script>"),
    ("official_domains",["paypal.com.evil.example/path"]), ("aliases",[]), ("sources",["http://example.com"]), ("id","<script>")])
def test_registry_rejects_unsafe_entries(monkeypatch, field, value):
    from app.brand import config
    data = load_registry()
    data["brands"][0][field] = value
    monkeypatch.setattr(config, "read_json", lambda _:data)
    with pytest.raises((ValueError, InvalidURL)):
        config.load_registry()


def test_equal_multibrand_claims_do_not_choose_arbitrary_impostor():
    result, _ = analyze("https://example.com", '<title>PayPal Microsoft</title><h1>PayPal Microsoft</h1><input type="password">')
    assert result["primary_brand"] is None and result["domain_match"] == "UNKNOWN"
    assert result["features"]["corroborated_brand_mismatch"] == 0


def test_metadata_urls_and_legal_links_are_context_only():
    result, _ = analyze("https://example.com", '<meta property="og:url" content="https://paypal.com/SECRET"><meta property="og:image" content="https://paypal.com/logo.png"><a href="/terms">Terms</a><a href="/contact">Contact</a>')
    assert result["primary_brand"] is None
    assert result["page_inventory"]["declared_domains"] == ["paypal.com"]
    assert result["page_inventory"]["legal_link_count"] == result["page_inventory"]["contact_link_count"] == 1
    assert "SECRET" not in json.dumps(result)


def test_one_official_auth_form_does_not_hide_another_unverified_collector():
    ctx = observations(phishing=False, probability=.02, reputation="SAFE")
    url = "https://paypal.com"
    ctx["web_intelligence"] = analyze_web_intelligence(url, '<title>PayPal</title><form action="https://paypal.com/auth"><input type="password"></form><form action="https://collect.example.net"><input type="password"></form>')
    ctx["brand_intelligence"] = analyze_brand(url, ctx["web_intelligence"], ctx["domain_intelligence"], enable_crawl=False, store=ObservationStore())
    assert ctx["brand_intelligence"]["features"]["official_auth_destination"] == 1
    assert ctx["brand_intelligence"]["features"]["external_nonofficial_credentials"] == 1
    result = RiskScoringEngine().calculate(ctx)
    assert result["verdict"] == "SUSPICIOUS"
