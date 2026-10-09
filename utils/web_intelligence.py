"""Explicit stage outcomes for bounded static HTML/content intelligence."""
from utils.safe_fetch import fetch_webpage_safely
from utils.html_features import extract_html_features, HTML_FEATURE_NAMES, HTMLResourceLimit
from utils.content_nlp import analyze_content_nlp
from utils.dynamic_analysis import analyze_webpage_dynamically
from app.behavior.analyzer import analyze_behavior
from app.behavior.privacy import redact_url

CONTENT_FEATURE_NAMES = ["login_language_score", "urgency_score", "credential_score", "financial_language_score",
    "security_language_score", "phishing_keyword_count", "brand_domain_mismatch"]


def analyze_web_intelligence(url, html_content_override=None):
    fetch = fetch_webpage_safely(url) if html_content_override is None else dict(status="SUCCESS", final_url=url,
        status_code=200, content_type="text/html", html_content=html_content_override,
        html_size=len(html_content_override.encode("utf8")), redirect_count=0, error_message=None)
    final_url = fetch.get("final_url") or url
    result = dict(status=fetch["status"], feature_version="5.1.1", fetch_summary={k:v for k,v in fetch.items() if k!='html_content'},
        html_features=dict.fromkeys(HTML_FEATURE_NAMES), content_features=dict.fromkeys(CONTENT_FEATURE_NAMES),
        combined_web_features=dict.fromkeys(HTML_FEATURE_NAMES + CONTENT_FEATURE_NAMES), forms=[], title="",
        canonical_url="", favicon_url="", resources=[], indicators=[],
        dynamic_analysis=analyze_webpage_dynamically(final_url))
    result["fetch_summary"]["final_url"] = redact_url(final_url)
    result["behavior_intelligence"] = analyze_behavior(url, fetch)
    def indicator(code, severity, value, reason):
        result["indicators"].append(dict(code=code, severity=severity, value=value, reason=reason,
                                        description=reason, source="StaticWebAnalysis"))
    if fetch["status"] != "SUCCESS":
        indicator(fetch["status"], "INFO", None, "Webpage evidence is unavailable; no safety conclusion is possible.")
        return result
    try:
        html = extract_html_features(fetch.get("html_content") or "", final_url)
        content = analyze_content_nlp(fetch.get("html_content") or "", html["title"], final_url)
    except HTMLResourceLimit:
        result["status"] = "RESOURCE_LIMIT_EXCEEDED"
        indicator(result["status"], "INFO", None, "Static analysis exceeded resource limits.")
        return result
    except Exception:
        result["status"] = "HTML_PARSE_FAILED"
        indicator(result["status"], "INFO", None, "Static webpage analysis could not complete.")
        return result
    result.update(status="ANALYZED", html_features=html["html_features"], content_features=content["content_features"],
        _brand_inventory=html["brand_inventory"],
        combined_web_features={**html["html_features"], **content["content_features"]}, forms=html["forms"],
        title=html["title"], canonical_url=html["canonical_url"], favicon_url=html["favicon_url"], resources=html["resources"])
    result["behavior_intelligence"] = analyze_behavior(url, fetch, html["static_behavior"], html["html_features"])
    # Internal routing target is used only by the scan service and removed at the public boundary.
    result["_analysis_target"] = final_url
    for form in html["forms"]:
        if form["is_credential_form"]:
            indicator("EXTERNAL_CREDENTIAL_FORM" if form["is_external"] else "PASSWORD_FORM_PRESENT",
                      "HIGH" if form["is_external"] else "INFO", form["action_domain"],
                      "Credential form submits to a different domain." if form["is_external"] else "Password form detected; this alone is not phishing.")
    if content["brand_mismatch_detected"]:
        indicator("BRAND_DOMAIN_MISMATCH", "MEDIUM", content["detected_brand"], "Page title and known brand domain differ.")
    for key, code in [("obfuscated_script_count", "OBFUSCATED_SCRIPT_DETECTED"),
                      ("external_iframe_count", "EXTERNAL_IFRAME_DETECTED"),
                      ("canonical_domain_mismatch", "CANONICAL_DOMAIN_MISMATCH"),
                      ("favicon_domain_mismatch", "FAVICON_DOMAIN_MISMATCH")]:
        if html["html_features"][key]: indicator(code, "LOW", html["html_features"][key], "Static structural signal; not an automatic phishing classification.")
    if content["content_features"]["urgency_score"] >= .5:
        indicator("URGENT_PHISHING_LANGUAGE", "LOW", content["content_features"]["urgency_score"], "Urgency wording detected; context is needed.")
    return result
