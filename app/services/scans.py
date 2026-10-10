"""One integrated URL pipeline, explicit missingness and evidence-based decisions."""
from functools import lru_cache
import time
from urllib.parse import urlsplit
from flask import current_app
from app.security.urls import validate_url
from utils.url_features import extract_advanced_url_features
from utils.url_indicators import analyze_url_indicators
from utils.domain_intelligence import analyze_domain_intelligence
from utils.web_intelligence import analyze_web_intelligence
from ml.features import aggregate_feature_dict
from ml.inference import SecureSightPredictor
from app.behavior.privacy import redact_url, sanitize_public_web
from app.brand.analyzer import analyze_brand, validate_email_context


@lru_cache(maxsize=1)
def _models():
    predictor = SecureSightPredictor()
    url_status = predictor.load()
    # Legacy email pickle has no approved Phase 11 evaluation/provenance.
    return {
        "url": predictor if predictor._loaded else None,
        "url_load_status": url_status,
        "email": None,
    }


def load_models(app):
    app.extensions["models"] = dict(_models())
    app.extensions["ml_predictor"] = app.extensions["models"]["url"]
    if app.extensions["ml_predictor"] is None:
        app.logger.warning(
            "url_model_unavailable",
            extra={
                "model_load_status": app.extensions["models"]["url_load_status"].get("status"),
                "model_failure_reason": app.extensions["models"]["url_load_status"].get("failure_reason"),
            },
        )


def _unavailable_prediction(load_status):
    """Expose the model loader's safe diagnostic in scan results."""
    result = {
        "status": load_status.get("status", "MODEL_NOT_FOUND"),
        "probability": None,
        "prediction": None,
    }
    if load_status.get("failure_reason"):
        result["failure_reason"] = load_status["failure_reason"]
    return result


def scan_url(value, email_context=None):
    start = time.perf_counter()
    url = validate_url(value, current_app.config["MAX_URL_LENGTH"])
    email_context = validate_email_context(email_context)
    timings = {}
    before = time.perf_counter()
    features = extract_advanced_url_features(url)
    # Preserve raw Unicode evidence lost by hostname normalization.
    features["unicode_detected"] = int(any(ord(c)>127 for c in value))
    advanced = analyze_url_indicators(url, features)
    timings["url_ms"] = round((time.perf_counter()-before)*1000,2)
    warnings_list = []
    before = time.perf_counter()
    try:
        domain = analyze_domain_intelligence(url)
    except Exception:
        domain = dict(status="ANALYSIS_FAILED", dns={}, tls={}, registration={}, reputation={}, domain_features={}, indicators=[])
        warnings_list.append("DOMAIN_ANALYSIS_FAILED")
    timings["domain_ms"] = round((time.perf_counter()-before)*1000,2)
    before = time.perf_counter()
    try:
        webpage = analyze_web_intelligence(url)
    except Exception:
        webpage = dict(status="ANALYSIS_FAILED", combined_web_features={}, fetch_summary={}, forms=[], indicators=[])
        warnings_list.append("WEB_ANALYSIS_FAILED")
    timings["web_ms"] = round((time.perf_counter()-before)*1000,2)
    final_target = webpage.pop("_analysis_target", url)
    behavior = webpage.get("behavior_intelligence")
    analysis_target = url
    if isinstance(behavior, dict) and behavior.get("final_destination_reached") and behavior.get("chain") and final_target != url:
        analysis_target = validate_url(final_target, current_app.config["MAX_URL_LENGTH"])
        features = extract_advanced_url_features(analysis_target)
        advanced = analyze_url_indicators(analysis_target, features)
        initial_parts, final_parts = urlsplit(url), urlsplit(analysis_target)
        if (initial_parts.scheme, initial_parts.netloc) != (final_parts.scheme, final_parts.netloc):
            before = time.perf_counter()
            try:
                domain = analyze_domain_intelligence(analysis_target)
            except Exception:
                domain = dict(status="ANALYSIS_FAILED", dns={}, tls={}, registration={}, reputation={}, domain_features={})
                warnings_list.append("FINAL_DOMAIN_ANALYSIS_FAILED")
            timings["final_domain_ms"] = round((time.perf_counter()-before)*1000,2)
    before = time.perf_counter()
    brand = analyze_brand(analysis_target, webpage, domain, original_url=value, email_context=email_context)
    timings["brand_ms"] = round((time.perf_counter()-before)*1000, 2)
    current_app.logger.info("brand_analysis_completed", extra={"phase":"9", "status":brand["status"],
        "duration_ms":timings["brand_ms"]})
    vector = aggregate_feature_dict(features, domain, webpage)
    predictor = current_app.extensions.get("ml_predictor")
    if current_app.extensions["models"]["url"] is None:
        predictor = None
    load_status = current_app.extensions["models"].get("url_load_status", {})
    unavailable_status = load_status.get("status", "MODEL_NOT_FOUND")
    prediction = predictor.predict(vector) if predictor is not None else _unavailable_prediction(load_status)
    probability = prediction.get("probability")
    if prediction["status"] != "OK":
        warnings_list.append(prediction["status"])
    dns = domain.get("dns", {})
    if dns.get("status") != "SUCCESS":
        warnings_list.append("DNS_UNAVAILABLE")
    elif not dns.get("is_ssrf_safe"):
        warnings_list.append("OUTBOUND_DESTINATION_BLOCKED")
    if webpage.get("status") != "ANALYZED":
        warnings_list.append("WEBPAGE_"+webpage.get("status","UNAVAILABLE"))
    if domain.get("registration",{}).get("status") not in {"AVAILABLE","PARTIAL"}:
        warnings_list.append("REGISTRATION_UNAVAILABLE")
    if domain.get("reputation",{}).get("reputation_status") in {"UNKNOWN","UNAVAILABLE","ERROR",None}:
        warnings_list.append("REPUTATION_UNCONFIRMED")
    if url.startswith("https:") and not domain.get("tls",{}).get("certificate_valid"):
        warnings_list.append("TLS_UNCONFIRMED")
    # Phase 6 consumes observations; all score/verdict policy lives in one engine.
    before = time.perf_counter()
    assessment = current_app.extensions["risk_engine"].calculate({
        "url_features":features, "url_indicators":advanced["indicators"],
        "domain_intelligence":domain, "web_intelligence":webpage,
        "ml_result":prediction, "scheme":analysis_target.split(":",1)[0], "feature_schema_version":"5.1.1",
        "behavior_intelligence":behavior, "brand_intelligence":brand})
    timings["risk_ms"] = round((time.perf_counter()-before)*1000,2)
    before = time.perf_counter()
    explanation = current_app.extensions["explanation_engine"].explain(assessment, prediction, webpage)
    timings["explanation_ms"] = round((time.perf_counter()-before)*1000,2)
    labels={"LEGITIMATE":"No strong phishing indicators", "SUSPICIOUS":"Suspicious", "PHISHING":"Phishing",
            "UNKNOWN":"Analysis incomplete", "ANALYSIS_FAILED":"Analysis incomplete"}
    decision=labels[assessment["verdict"]]
    evidence=[s["signal_id"] for s in assessment["top_signals"]]
    for rule in assessment.get("audit",{}).get("risk_adjustments",[]):
        evidence.append(rule["rule"])
    warning_codes=list(dict.fromkeys(warnings_list+[w["code"] for w in assessment["warnings"]]))
    current_app.logger.info("risk_assessment_completed", extra={
        "assessment_version":assessment["assessment_version"],"scoring_config_version":assessment["scoring_config_version"],
        "scoring_config_sha256":assessment["scoring_config_sha256"],"risk_score":assessment["risk_score"],
        "confidence":assessment["confidence"],"verdict":assessment["verdict"],
        "evidence_coverage":assessment["evidence_coverage"],"signal_ids":evidence})
    if behavior is not None:
        current_app.logger.info("redirect_analysis_completed", extra={"phase":"8", "status":behavior["status"],
            "duration_ms":behavior["resources"]["elapsed_ms"], "redirect_count":behavior["redirect_count"],
            "unique_domains":behavior["unique_registrable_domains"], "error_code":None if behavior["status"] == "ANALYZED" else behavior["status"]})
    sanitize_public_web(webpage, final_target)
    return dict(url=redact_url(url),analysis_target=redact_url(analysis_target),behavior_intelligence=behavior,
        brand_intelligence=brand, brand_feature_version="9.0.0",
        behavior_feature_version="8.0.0",decision=decision,status="PARTIAL" if warning_codes else "ANALYZED",
        assessment=assessment, risk_score=assessment["risk_score"],risk_score_kind="heuristic observed risk; not a safety probability",
        severity=assessment["severity"], verdict=assessment["verdict"],confidence=assessment["confidence"],
        confidence_kind=assessment["confidence_kind"],confidence_calibrated=assessment["confidence_calibrated"],
        evidence_coverage=assessment["evidence_coverage"],analysis_completeness=assessment["analysis_completeness"],
        category_scores=assessment["category_scores"],top_signals=assessment["top_signals"],
        contradictions=assessment["contradictions"],missing_signals=assessment["missing_signals"],
        assessment_version=assessment["assessment_version"],scoring_config_version=assessment["scoring_config_version"],
        assessment_warnings=assessment["warnings"],model_version=assessment["model_version"],
        ml_probability=probability,model_available=predictor is not None,ml_result=prediction,feature_schema_version="5.1.1",
        feature_vector=vector, evidence=evidence, warnings=warning_codes,
        timings={**timings,"total_ms":round((time.perf_counter()-start)*1000,2)},
        explanation={**explanation, "ml_detail":{"model_status":prediction["status"],"model_scope":prediction.get("model_scope"),
            "model_version":prediction.get("model_version"),"decision":decision,"explanations":prediction.get("explanations",[])},
            "risk_breakdown":{"Observed evidence":", ".join(evidence) or "None","Limitations":", ".join(warning_codes) or "None",
            "Risk meaning":"Heuristic observed risk, not a guarantee","Model probability":probability,
            "Confidence kind":assessment["confidence_kind"]}},
        advanced_analysis={"features":features,**advanced,"feature_version":"5.1.1"},
        domain_intelligence=domain,web_intelligence=webpage)

def scan_email(text):
    if not isinstance(text, str) or not text.strip() or len(text) > current_app.config["MAX_EMAIL_LENGTH"]:
        raise ValueError("Invalid email content")
    from app.email.service import analyze
    analysis = analyze(text.encode("utf-8"), budget_seconds=38)
    return format_email_result(analysis)


def format_email_result(analysis):
    risk = analysis["risk"]
    labels = {"PHISHING": "Phishing", "SUSPICIOUS": "Suspicious"}
    return {"type": "email", "content_snippet": analysis["body_analysis"]["snippet"],
            "decision": labels.get(risk["verdict"], "Analysis incomplete"), "ml_probability": None,
            "model_available": False, "warnings": ["EMAIL_MODEL_UNAVAILABLE"], "email_analysis": analysis}, {
                "features": analysis["body_analysis"]["features"], **analysis["explanation"]}
