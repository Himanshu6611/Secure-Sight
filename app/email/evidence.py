"""Known evidence IDs and fixed explanations; confidence is not fabricated."""
REASONS = {
    "DUPLICATE_IDENTITY_HEADER": ("HEADER", "Duplicate identity headers make sender interpretation ambiguous."),
    "MIME_DEFECT": ("HEADER", "The MIME parser observed malformed message structure or encoding."),
    "REPLY_TO_DOMAIN_MISMATCH": ("REPLY_TO", "Reply-To and From use different registrable domains; third-party routing can also explain this."),
    "SENDER_DOMAIN_MISMATCH": ("SENDER", "Sender and From use different registrable domains; this alone is not impersonation."),
    "RETURN_PATH_DOMAIN_MISMATCH": ("RETURN_PATH", "Return-Path differs from From; delegated sending infrastructure can be legitimate."),
    "UNICODE_IDENTITY": ("SENDER", "The identity contains Unicode, normalization or confusable-character observations."),
    "DISPLAY_BRAND_DOMAIN_MISMATCH": ("BRAND", "The visible sender claims a registered brand whose official domains differ from the From domain."),
    "RECEIVED_CHRONOLOGY_ANOMALY": ("HEADER", "Uploaded Received timestamps have unusual ordering; hops are not independently trusted."),
    "TIMESTAMP_ANOMALY": ("HEADER", "A message timestamp is inconsistent with ingestion or claimed receiving time."),
    "HTML_LINK_DOMAIN_MISMATCH": ("URL", "Displayed link and actual destination use different registrable domains."),
    "SOCIAL_ENGINEERING_LANGUAGE": ("EMAIL_NLP", "Contextual pressure, credential or payment language was observed; keywords alone do not establish phishing."),
    "BEC_CONTEXT_COMBINATION": ("BEC", "Payment redirection or executive/secrecy language is combined with urgency or Reply-To differences; this is a BEC candidate, not proven fraud."),
    "DANGEROUS_ATTACHMENT": ("ATTACHMENT", "An attachment has executable, macro-capable or archive security indicators; it was not executed."),
    "AUTHENTICATION_UNVERIFIED": ("EMAIL_AUTHENTICATION", "Uploaded authentication claims are untrusted and trusted SMTP peer/envelope data is unavailable."),
    "AUTHENTICATION_SIGNATURE_FAILED": ("EMAIL_AUTHENTICATION", "A cryptographic signature did not validate or was malformed; this alone does not prove phishing."),
    "RESOURCE_OR_PROVIDER_LIMIT": ("EMAIL", "Some intelligence could not be completed within its provider or resource budget."),
}


def build(result):
    found = []
    headers = result["message"]["headers"]
    def add(indicator, value, source, kind="OBSERVED"):
        category, _ = REASONS[indicator]
        found.append({"evidence_id": f"EMAIL-{len(found):03d}-{indicator}", "category": category,
            "indicator": indicator, "severity": "INFO", "value": value, "confidence": None,
            "source": source, "evidence_type": kind, "timestamp": headers["timestamps"]["ingested_at"],
            "email_id": result["message"]["email_id"], "independence_group": "EMAIL_IDENTITY" if category in {"HEADER", "SENDER", "REPLY_TO", "RETURN_PATH", "BRAND"} else category})
    if headers["duplicate_headers"]:
        add("DUPLICATE_IDENTITY_HEADER", headers["duplicate_headers"], "header_analyzer")
    if result["message"]["defects"]:
        add("MIME_DEFECT", result["message"]["defects"], "mime_parser")
    for field, indicator in (("reply-to", "REPLY_TO_DOMAIN_MISMATCH"), ("sender", "SENDER_DOMAIN_MISMATCH"), ("return-path", "RETURN_PATH_DOMAIN_MISMATCH")):
        if headers["relationships"][field] == "MISALIGNED":
            add(indicator, True, "header_analyzer")
    if headers["unicode_indicators"]:
        add("UNICODE_IDENTITY", headers["unicode_indicators"], "identity_normalizer")
    if result["brands"]["display_name_impersonation"]:
        add("DISPLAY_BRAND_DOMAIN_MISMATCH", result["brands"]["display_name_impersonation"], "brand_registry", "INFERRED")
    if headers["received"]["chronology_anomaly"]:
        add("RECEIVED_CHRONOLOGY_ANOMALY", True, "received_analyzer")
    if headers["timestamps"]["future_date"] or headers["timestamps"]["date_after_received"]:
        add("TIMESTAMP_ANOMALY", True, "timestamp_analyzer")
    body = result["body_analysis"]
    if body["html"]["url_mismatches"]:
        add("HTML_LINK_DOMAIN_MISMATCH", body["html"]["url_mismatches"], "html_email_analyzer")
    if any(body["features"].values()):
        add("SOCIAL_ENGINEERING_LANGUAGE", [k for k, v in body["features"].items() if v], "body_analyzer")
    if body["bec"]["candidate"]:
        add("BEC_CONTEXT_COMBINATION", True, "bec_analyzer", "INFERRED")
    risky = [a["sha256"] for a in result["attachments"] if set(a["indicators"]) & {"EXECUTABLE_ATTACHMENT", "DOUBLE_EXTENSION_EXECUTABLE", "MACRO_ATTACHMENT", "MACRO_CAPABLE_ATTACHMENT", "EXECUTABLE_ARCHIVE_MEMBER", "ARCHIVE_PATH_TRAVERSAL", "ARCHIVE_RESOURCE_LIMIT"}]
    if risky:
        add("DANGEROUS_ATTACHMENT", risky, "attachment_analyzer")
    add("AUTHENTICATION_UNVERIFIED", True, "authentication_analyzer", "MISSING")
    if result["authentication"]["dkim"]["result"] in {"FAIL", "PERMERROR"}:
        add("AUTHENTICATION_SIGNATURE_FAILED", True, "dkim_verifier", "EXTERNAL")
    if result["errors"]:
        add("RESOURCE_OR_PROVIDER_LIMIT", [e["code"] for e in result["errors"]], "email_orchestrator", "MISSING")
    return found
