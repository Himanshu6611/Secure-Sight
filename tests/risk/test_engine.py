"""Policy boundaries, independence, partial evidence, security and integration."""
import copy
import json
import math
import pytest
from dataclasses import replace
from app.risk.config import load_config, validate_config
from app.risk.engine import RiskScoringEngine
from app.risk.normalization import normalize
from app.risk.aggregation import aggregate
from app.risk.confidence import confidence
from app.risk.verdict import severity, verdict
from app.risk.schemas import RiskError
from app.risk.schemas import Signal
from utils.url_features import extract_advanced_url_features
from utils.url_indicators import analyze_url_indicators
from utils.web_intelligence import analyze_web_intelligence

@pytest.fixture
def engine():
    return RiskScoringEngine()

def context(probability=.02, reputation="SAFE", phishing=False):
    url="https://verify-paypal-account.example.net/login" if phishing else "https://example.com/"
    html=('<title>PayPal Account Verification</title><p>Urgent: account suspended. Confirm password immediately.</p>'
        '<h1>PayPal account login</h1>'
        '<form action="//collect.example.org/login"><input type="password"></form>') if phishing else (
        '<title>Example Portal</title><form action="/login"><input type="password"></form>')
    return {
        "url_features":extract_advanced_url_features(url),
        "url_indicators":analyze_url_indicators(url,extract_advanced_url_features(url))["indicators"],
        "domain_intelligence":{
            "dns":{"status":"SUCCESS","is_ssrf_safe":True},
            "tls":{"status":"VALID","certificate_valid":True},
            "registration":{"status":"AVAILABLE","domain_age_days":3650},
            "reputation":{"reputation_status":reputation,
                "providers":[{"provider":"fixture","status":reputation,"confidence":.99}] if reputation in {"SAFE","MALICIOUS"} else []}},
        "web_intelligence":analyze_web_intelligence(url,html),
        "ml_result":{"status":"OK","probability":probability,"prediction":"phishing" if probability>=.93 else "legitimate",
            "model_version":"5.1.1","feature_schema_version":"5.1.1","model_validated":True,"calibration_method":"sigmoid"},
        "scheme":"https","feature_schema_version":"5.1.1",
    }

@pytest.mark.parametrize("score,name",[(0,"VERY_LOW"),(19,"VERY_LOW"),(20,"LOW"),(39,"LOW"),
    (40,"MEDIUM"),(59,"MEDIUM"),(60,"HIGH"),(79,"HIGH"),(80,"CRITICAL"),(100,"CRITICAL")])
def test_severity_boundaries(score,name):
    assert severity(score,load_config())==name

@pytest.mark.parametrize("value,formula,expected",[
    (True,"boolean",1),(False,"boolean",0),(0,"inverse_boolean",1),(1,"inverse_boolean",0),
    (4,"ramp",.4),(12,"ramp",1),(4,"inverse_ramp",.6),(0,"inverse_ramp",1),
    (.91,"probability",.91),(None,"probability",None),
])
def test_normalization(value,formula,expected):
    assert normalize(value,{"formula":formula,"maximum":1.,"low":0,"high":10})==pytest.approx(expected) if expected is not None else normalize(value,{"formula":formula,"maximum":1.}) is None

@pytest.mark.parametrize("bad",[-1,math.nan,math.inf,"0.8",[],{}])
def test_invalid_numeric_signal(bad):
    with pytest.raises(RiskError):
        normalize(bad,{"formula":"probability","maximum":1})

@pytest.mark.parametrize("bad",[2,"true",None])
def test_invalid_boolean_signal(bad):
    if bad is None:
        assert normalize(bad,{"formula":"boolean","maximum":1}) is None
    else:
        with pytest.raises(RiskError):
            normalize(bad,{"formula":"boolean","maximum":1})

def test_legitimate(engine):
    result=engine.calculate(context())
    assert result["status"]=="OK"
    assert result["verdict"]=="LEGITIMATE"
    assert result["risk_score"]<20
    assert result["confidence"]>=65
    assert result["confidence"]!=result["ml_probability"]*100
    assert result["confidence_calibrated"] is False

def test_strong_agreement(engine):
    result=engine.calculate(context(.99,"MALICIOUS",True))
    assert result["risk_score"]>=85
    assert result["confidence"]>=70
    assert result["verdict"]=="PHISHING"
    assert result["agreement"]=="HIGH"
    assert len(result["independent_risk_sources"])==3
    assert not result["contradictions"]

def test_phishing_without_reputation_requires_independent_web(engine):
    result=engine.calculate(context(.99,"UNKNOWN",True))
    assert result["risk_score"]>=80
    assert result["evidence_coverage"]==80
    assert result["verdict"]=="PHISHING"
    assert len(result["independent_risk_sources"])==2

def test_model_alone_cannot_force_phishing(engine):
    result=engine.calculate(context(.99,"UNKNOWN"))
    assert result["verdict"]=="SUSPICIOUS"
    assert len(result["independent_risk_sources"])==1

def test_reputation_conflict(engine):
    agree=engine.calculate(context(.99,"MALICIOUS",True))
    result=engine.calculate(context(.99,"SAFE",True))
    assert result["confidence"]<agree["confidence"]
    assert result["verdict"]=="SUSPICIOUS"
    assert result["agreement"]=="LOW"
    assert "ML_REPUTATION_CONFLICT" in [c["code"] for c in result["contradictions"]]

def test_media_model_unavailable_is_unknown_not_an_assessment_failure(engine):
    result = engine.assess_media({"linked_analysis": []})
    assert result["status"] == "PARTIAL"
    assert result["verdict"] == "UNKNOWN"
    assert result["risk_score"] is None
    assert result["confidence"] is None
    assert result["evidence_coverage"] is None
    assert result["warnings"][0]["code"] == "MEDIA_AUTHENTICITY_UNVERIFIED"
    assert "Assessment failed" not in result["warnings"][0]["message"]

def test_email_without_assessed_destination_is_unknown_not_an_assessment_failure(engine):
    result = engine.assess_email({"evidence": [], "urls": []})
    assert result["status"] == "PARTIAL"
    assert result["verdict"] == "UNKNOWN"
    assert result["risk_score"] is None
    assert result["confidence"] is None
    assert result["evidence_coverage"] is None
    assert result["warnings"][0]["code"] == "EMAIL_INTELLIGENCE_INCOMPLETE"
    assert "Assessment failed" not in result["warnings"][0]["message"]

def test_low_model_conflicts_with_harvesting(engine):
    result=engine.calculate(context(.01,"UNKNOWN",True))
    assert result["risk_score"]>=60
    assert result["verdict"]=="SUSPICIOUS"
    assert result["contradictions"]
    assert result["confidence"]<70

@pytest.mark.parametrize("missing",["dns","tls","registration","reputation","html","content","ml"])
def test_missing_evidence_not_safe(engine,missing):
    ctx=context()
    if missing in {"dns","tls","registration"}:
        ctx["domain_intelligence"][missing]={"status":"TIMEOUT"}
    elif missing=="reputation":
        ctx["domain_intelligence"]["reputation"]={"reputation_status":"UNAVAILABLE","providers":[]}
    elif missing=="html":
        ctx["web_intelligence"]={"status":"TIMEOUT","combined_web_features":{}}
    elif missing=="content":
        for name in ("urgency_score","credential_score","financial_language_score","brand_domain_mismatch"):
            ctx["web_intelligence"]["combined_web_features"][name]=None
    else:
        ctx["ml_result"]={"status":"MODEL_NOT_FOUND","probability":None,"prediction":None}
    full=engine.calculate(context()); result=engine.calculate(ctx)
    assert result["status"]=="OK"
    assert result["confidence"]<full["confidence"]
    assert result["evidence_coverage"]<full["evidence_coverage"]
    assert result["missing_signals"]
    if missing in {"dns","html","ml"}:
        assert result["verdict"]=="UNKNOWN"

def test_all_stages_missing_analysis_failed(engine):
    result=engine.calculate({"url_features":{},"domain_intelligence":{},"web_intelligence":{},"ml_result":{}})
    assert result["risk_score"] is None
    assert result["verdict"]=="ANALYSIS_FAILED"
    assert result["confidence"]==0

def test_http_tls_not_applicable(engine):
    ctx=context();ctx["scheme"]="http";ctx["domain_intelligence"]["tls"]={}
    result=engine.calculate(ctx)
    assert result["audit"]["stages"]["tls"]=="NOT_APPLICABLE"
    assert not any(s["signal_id"]=="tls.invalid" for s in result["missing_signals"])
    assert result["evidence_coverage"]==100

def test_unsafe_dns_and_tls_prevent_legitimate(engine):
    ctx=context();ctx["domain_intelligence"]["dns"]["is_ssrf_safe"]=False
    assert engine.calculate(ctx)["verdict"]!="LEGITIMATE"
    ctx=context();ctx["domain_intelligence"]["tls"]={"status":"INVALID","certificate_valid":False}
    assert engine.calculate(ctx)["verdict"]!="LEGITIMATE"

def test_historical_suspicion_is_not_safe(engine):
    result=engine.calculate(context(.02,"SUSPICIOUS"))
    assert result["verdict"]=="SUSPICIOUS"
    assert "REPUTATION_MATCH_UNCONFIRMED" in [w["code"] for w in result["warnings"]]

def test_double_count_prevention_and_audit_reconstruction(engine):
    ctx=context(.99,"MALICIOUS",True)
    result=engine.calculate(ctx)
    duplicated=copy.deepcopy(ctx)
    duplicated["web_intelligence"]["forms"]*=20
    duplicated["web_intelligence"]["indicators"]*=20
    assert engine.calculate(duplicated)==result
    contributions=sum(s["contribution"] for s in result["signals"])
    assert contributions==pytest.approx(result["audit"]["base_risk_score"])
    assert len([s for s in result["signals"] if s["selected"]])==len(set((s["category"],s["group"]) for s in result["signals"] if s["selected"]))

def test_determinism_no_mutation_or_network(engine,monkeypatch):
    import socket
    original=context(.99,"MALICIOUS",True)
    ctx=copy.deepcopy(original)
    monkeypatch.setattr(socket,"create_connection",lambda *a,**kw:pytest.fail("Scoring attempted network I/O"))
    baseline=engine.calculate(ctx)
    for _ in range(20):
        assert engine.calculate(ctx)==baseline
    assert ctx==original
    assert "example.net" not in json.dumps(baseline)
    assert "collect.example.org" not in json.dumps(baseline)

@pytest.mark.parametrize("probability",[0,.02,.15,.5,.85,.99,1])
def test_confidence_bounds(engine,probability):
    for rep in ("UNKNOWN","SAFE","MALICIOUS"):
        result=engine.calculate(context(probability,rep,probability>.5))
        assert 0<=result["confidence"]<=100
        assert 0<=result["risk_score"]<=100
        assert 0<=result["evidence_coverage"]<=100

def test_direct_verdict_confidence_zero_and_hundred():
    config=load_config();flags={"essential_complete":True,"dns_safe":True,"observed_web":True}
    assert verdict(0,0,100,flags,set(),[],config)=="UNKNOWN"
    assert verdict(0,100,100,flags,set(),[],config)=="LEGITIMATE"
    assert verdict(100,100,100,flags,{"URL_MODEL","STATIC_WEB"},[],config)=="PHISHING"

@pytest.mark.parametrize("bad",[None,{},[],{"url_features":[]}])
def test_invalid_context_fails_closed(engine,bad):
    result=engine.calculate(bad)
    assert result["status"]=="ERROR"
    assert result["verdict"]=="ANALYSIS_FAILED"
    assert result["risk_score"] is None
    assert result["error"]["code"] in {"MISSING_ANALYSIS_CONTEXT","RISK_INPUT_INVALID"}

@pytest.mark.parametrize("bad",[math.nan,math.inf,-.1,1.1,"0.9"])
def test_invalid_input_signal_fails_closed(engine,bad):
    ctx=context();ctx["ml_result"]["probability"]=bad
    result=engine.calculate(ctx)
    assert result["verdict"]=="ANALYSIS_FAILED"
    assert result["error"]["code"]=="INVALID_SIGNAL"

def test_unverified_model_or_provider_cannot_establish_safety(engine):
    ctx=context();ctx["ml_result"]["model_validated"]=False
    assert engine.calculate(ctx)["verdict"]=="UNKNOWN"
    ctx=context();ctx["domain_intelligence"]["reputation"]["providers"][0]["confidence"]=.2
    result=engine.calculate(ctx)
    assert result["category_scores"]["reputation"] is None
    assert result["evidence_coverage"]==80

@pytest.mark.parametrize("mutation",["weight","extra","severity","verdict","nan","formula"])
def test_config_invalid(mutation):
    cfg=load_config()
    if mutation=="weight":cfg["categories"]["ml"]=2
    elif mutation=="extra":cfg["execute"]="__import__('os').system('bad')"
    elif mutation=="severity":cfg["severity"][1]["minimum"]=0
    elif mutation=="verdict":cfg["verdict"]["phishing_min_risk"]=10
    elif mutation=="nan":cfg["confidence"]["model"]=math.nan
    else:cfg["signals"][0]["formula"]="execute"
    with pytest.raises(RiskError):
        validate_config(cfg)

def test_config_is_copied_and_identified(engine):
    cfg=engine.config
    cfg["categories"]["url"]=9
    assert engine.config["categories"]["url"]==.15
    result=engine.calculate(context())
    assert result["assessment_version"]==result["scoring_config_version"]=="6.2.1"
    assert len(result["scoring_config_sha256"])==64

def test_single_weak_signal_cannot_mark_phishing(engine):
    ctx=context()
    ctx["url_features"]["punycode_detected"]=1
    result=engine.calculate(ctx)
    assert result["verdict"]=="LEGITIMATE"

def test_not_applicable_brand_distance_sentinel_is_not_negative_risk(engine):
    ctx=context()
    ctx["url_features"]["min_brand_distance"]=-1
    ctx["ml_result"]={"status":"MISSING_REQUIRED_FEATURE","probability":None}
    result=engine.calculate(ctx)
    assert result["status"]=="OK"
    assert result["verdict"]=="UNKNOWN"

def test_confidence_calculation_zero_and_hundred():
    config=load_config()
    empty_flags={"ml_probability":None,"model_calibrated":False,"essential_complete":False}
    assert confidence([],0,empty_flags,config)[0]==0
    signals=[Signal("ml.phishing","ML","model","model",1,1,1,"HIGH","phase_5",1,"fixture","AVAILABLE",True),
        Signal("reputation.provider","REPUTATION","provider","provider","MALICIOUS",1,1,"HIGH","phase_3_reputation",1,"fixture","AVAILABLE",True)]
    flags={"ml_probability":1.,"model_calibrated":True,"essential_complete":True,"reputation_malicious":True}
    assert confidence(signals,100,flags,config)[0]==100

def test_duplicate_json_keys_rejected(tmp_path):
    from app.risk.config import load_config
    path=tmp_path/"ambiguous.json"
    path.write_text('{"version":"6.0.0","version":"bad"}')
    with pytest.raises(RiskError,match="SCORING_CONFIGURATION_ERROR"):
        load_config(path)

def test_missing_calibration_cannot_trigger_model_web_floor(engine):
    ctx=context(.99,"UNKNOWN",True)
    ctx["ml_result"]["calibration_method"]=None
    result=engine.calculate(ctx)
    assert result["verdict"]!="PHISHING"
    assert not any(r["rule"]=="MODEL_AND_CORROBORATED_HARVESTING" for r in result["audit"]["risk_adjustments"])

def test_partial_content_not_counted_as_completed(engine):
    ctx=context()
    ctx["web_intelligence"]["combined_web_features"]["urgency_score"]=None
    result=engine.calculate(ctx)
    assert result["audit"]["stages"]["content"]=="PARTIAL"
    assert result["analysis_completeness"]<100

def test_query_at_symbol_is_not_authority_obfuscation(engine):
    ctx=context()
    url="https://example.com/?email=me@example.org"
    ctx["url_features"]=extract_advanced_url_features(url)
    ctx["url_indicators"]=analyze_url_indicators(url,ctx["url_features"])["indicators"]
    result=engine.calculate(ctx)
    assert next(s for s in result["signals"] if s["signal_id"]=="url.at_authority")["normalized_value"]==0

def test_integrated_api_canonical_assessment_and_safe_audit_log(client,app,monkeypatch):
    from app.services import scans
    ctx=context(.99,"MALICIOUS",True)
    monkeypatch.setattr(scans,"analyze_domain_intelligence",lambda *a:ctx["domain_intelligence"])
    monkeypatch.setattr(scans,"analyze_web_intelligence",lambda *a:ctx["web_intelligence"])
    class Predictor:
        def predict(self,*a,**kw):
            return ctx["ml_result"]
    app.extensions["ml_predictor"]=Predictor()
    result=client.post("/api/v1/scan",json={"url":"https://verify-paypal-account.example.net/login"}).json
    assert result["verdict"]=="PHISHING"
    assert result["risk_score"]==result["assessment"]["risk_score"]
    assert result["confidence"]==result["assessment"]["confidence"]
    assert result["ml_probability"]==.99
    assert isinstance(result["assessment"]["warnings"][0],dict)

def test_scoring_failure_integration_cannot_be_green(client,monkeypatch):
    from app.services import scans
    ctx=context()
    ctx["domain_intelligence"]["registration"]["domain_age_days"]=-1
    monkeypatch.setattr(scans,"analyze_domain_intelligence",lambda *a:ctx["domain_intelligence"])
    response=client.post("/api/v1/scan",json={"url":"https://example.com/"})
    assert response.status_code==200
    assert response.json["verdict"]=="ANALYSIS_FAILED"
    assert response.json["risk_score"] is None
    assert response.json["decision"]=="Analysis incomplete"
