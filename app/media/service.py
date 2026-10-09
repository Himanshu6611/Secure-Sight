"""Media evidence orchestration; URLs reuse the complete existing website pipeline."""
import datetime
from flask import current_app
from .intake import MAX_BYTES, MediaError, validate
from .worker import run, run_linked

LANGUAGES = {"eng", "hin", "eng+hin", "ara", "chi_sim", "fra", "deu", "spa"}


def analyze(file, language="eng", email_context=None, source_url=None, url_analyzer=None,
            reverse_search=False, content_safety=False, requested_checks=None):
    if language not in LANGUAGES:
        raise MediaError("INVALID_MEDIA")
    data = file.stream.read(MAX_BYTES + 1)
    artifact = validate(data, file.mimetype)
    if file.filename:
        from pathlib import PurePosixPath
        extension = PurePosixPath(file.filename.replace("\\", "/")).suffix.lower()
        expected = {"image/png": {".png"}, "image/jpeg": {".jpg", ".jpeg"}, "image/webp": {".webp"}}
        if extension not in expected[artifact["mime"]]:
            raise MediaError("MAGIC_BYTES_MISMATCH", 415)
    from app.security.urls import validate_url, InvalidURL
    if source_url:
        source_url = validate_url(source_url)
    result = run(data, artifact, language)
    result.update(media_version="10.0.0", created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  retention="request_only", source="email_attachment" if email_context else "website_attachment" if source_url else "upload")
    result["synthid"] = {"status": "NOT_CHECKED", "provider": "GOOGLE_SYNTHID_DETECTOR",
        "reason_code": "MANUAL_CHECK_REQUIRED", "network_request": False,
        "message": "SecureSight does not submit images to the SynthID portal. Upload the image there yourself to check for its watermark."}
    registry = current_app.extensions["brand_registry"]
    text = result["ocr"]["text"].casefold()
    import re
    brands = [b["id"] for b in registry["brands"] if any(re.search(r"(?<!\w)" + re.escape(a.casefold()) + r"(?!\w)", text) for a in b["aliases"])]
    result["brand_analysis"] = {"observed_brands": brands, "claimed_brand": (email_context or {}).get("claimed_brand"),
        "source": "OCR_TEXT", "logo_match_confidence": None, "logo_analysis_status": "MODEL_UNAVAILABLE",
        "match_is_authenticity_proof": False, "registry_version": registry["version"]}
    linked, errors = [], []
    analyzed_destinations = []
    urls = result.pop("_urls")
    if source_url and source_url not in urls:
        urls.append(source_url)
    seen = set()
    for value in urls:
        if len(linked) + len(errors) >= 1:
            break
        try:
            normalized = validate_url(value)
            if normalized in seen:
                continue
            seen.add(normalized)
            linked.append((url_analyzer or run_linked)(normalized, email_context, current_app.config))
            analyzed_destinations.append(normalized)
        except InvalidURL:
            errors.append({"code": "INVALID_URL"})
        except MediaError as exc:
            errors.append({"code": "LINKED_" + exc.code})
        except Exception:
            errors.append({"code": "LINKED_ANALYSIS_FAILED"})
    result["linked_analysis"] = linked
    from urllib.parse import urlsplit
    from app.brand.analyzer import domain_match
    brand_lookup = {b["id"]: b for b in registry["brands"]}
    brand_correlations = []
    for url in seen:
        for brand in brands:
            brand_correlations.append({"brand": brand, "destination_hostname": urlsplit(url).hostname,
                "official_domain_relationship": domain_match(urlsplit(url).hostname, brand_lookup[brand]) or "UNMATCHED",
                "source": "OCR_TEXT_AND_EXTRACTED_URL", "score_contribution": 0,
                "interpretation": "A domain difference requires corroboration; it does not prove impersonation."})
    result["correlations"] = {"url_candidates": len(urls), "urls_analyzed": len(linked),
        "url_limit": 1, "errors": errors, "deduplication": "normalized_destination",
        "independent_media_risk_points": 0, "brand_destination_observations": brand_correlations,
        "destination_limit_reached": len(urls) > len(linked) + len(errors)}
    result["correlations"]["email_brand_observations"] = [
        {"brand": brand, "field": key, "domain_relationship": domain_match(email_context[key], brand_lookup[brand]) or "UNMATCHED",
         "authentication_status": "UNVERIFIED", "score_contribution": 0}
        for brand in brands for key in ("sender_domain", "reply_to_domain") if email_context and key in email_context]
    if source_url:
        result["correlations"]["source_hostname"] = urlsplit(source_url).hostname
        result["correlations"]["source_claim_verified"] = False
    evidence = ["media.model_unavailable", "media.measured_properties"]
    if result["quality"]["status"] == "INSUFFICIENT_QUALITY":
        evidence.append("media.insufficient_quality")
    if result["qr"]["items"]:
        evidence.append("media.qr_observed")
    if result["ocr"]["words"]:
        evidence.append("media.ocr_observed")
    if result["provenance"]["status"] == "ABSENT":
        evidence.append("media.provenance_absent")
    result["evidence"] = [{"id": item, "source_sha256": artifact["sha256"], "score_contribution": 0, "confidence": None} for item in evidence]
    result["assessment"] = current_app.extensions["risk_engine"].assess_media(result)
    result["explanation"] = current_app.extensions["explanation_engine"].explain_media(result)
    result["graph"] = {"nodes": [{"id": artifact["sha256"], "type": "IMAGE"}] +
        [{"id": f"url:{i}", "type": "URL", "assessment": scan.get("assessment")} for i, scan in enumerate(linked)],
        "edges": [{"source": artifact["sha256"], "target": f"url:{i}", "relationship": "EXTRACTED_DESTINATION"} for i in range(len(linked))]}
    for stage in ("ocr", "qr", "provenance"):
        node_id = artifact["sha256"] + ":" + stage
        result["graph"]["nodes"].append({"id": node_id, "type": stage.upper(), "status": result[stage]["status"]})
        result["graph"]["edges"].append({"source": artifact["sha256"], "target": node_id, "relationship": "HAS_EVIDENCE"})
    for i, destination in enumerate(analyzed_destinations):
        source_stage = "ocr"
        for item in result["qr"]["items"]:
            try:
                if item["type"] == "URL" and validate_url(item["payload"]) == destination:
                    source_stage = "qr"
                    break
            except InvalidURL:
                continue
        result["graph"]["edges"].append({"source": artifact["sha256"] + ":" + source_stage,
            "target": f"url:{i}", "relationship": "DECODED_DESTINATION", "independence_group": artifact["sha256"]})
    if email_context:
        result["graph"]["nodes"].append({"id": "email_context", "type": "EMAIL", "authentication_status": "UNVERIFIED"})
        result["graph"]["edges"].append({"source": "email_context", "target": artifact["sha256"], "relationship": "SUPPLIED_ATTACHMENT"})
    if source_url:
        result["graph"]["nodes"].append({"id": "website_context", "type": "WEBSITE", "hostname": urlsplit(source_url).hostname,
                                        "source_claim_verified": False})
        result["graph"]["edges"].append({"source": "website_context", "target": artifact["sha256"], "relationship": "SUPPLIED_SOURCE_CLAIM"})
    for brand in brands:
        result["graph"]["nodes"].append({"id": "media_brand:" + brand, "type": "BRAND", "value": brand})
        result["graph"]["edges"].append({"source": artifact["sha256"] + ":ocr", "target": "media_brand:" + brand,
            "relationship": "CONTAINS_BRAND_TEXT", "independence_group": artifact["sha256"]})
    for i, scan in enumerate(linked):
        website_graph = scan.get("brand_intelligence", {}).get("evidence_graph", {})
        for node in website_graph.get("nodes", [])[:64]:
            result["graph"]["nodes"].append({**node, "id": f"url:{i}:" + node["id"]})
        for edge in website_graph.get("edges", [])[:128]:
            result["graph"]["edges"].append({**edge, "source": f"url:{i}:" + edge["source"], "target": f"url:{i}:" + edge["target"]})
    result["analysis_status"] = "PARTIAL"
    result["errors"] = [{"code": "MODEL_UNAVAILABLE"}] + errors
    for stage, failure in (("ocr", "OCR_FAILED"), ("qr", "QR_DECODE_FAILED")):
        if result[stage]["status"] != "ANALYZED":
            result["errors"].append({"code": failure})
    current_app.logger.info("media_analysis_completed", extra={"phase": "10", "status": result["analysis_status"],
                            "verdict": result["assessment"]["verdict"], "error_code": "MODEL_UNAVAILABLE"})
    # Public results never retain QR credential payloads or URL query parameters.
    from urllib.parse import urlsplit
    for item in result["qr"]["items"]:
        payload = item.pop("payload")
        try:
            parsed = urlsplit(payload) if item["type"] == "URL" else None
            item["display"] = parsed.hostname if parsed else "Text payload redacted"
        except ValueError:
            item["display"] = "Invalid URL payload"
    from .report import build as build_investigation
    result["investigation"] = build_investigation(result, reverse_search=reverse_search,
        content_safety=content_safety, requested_checks=requested_checks)
    return result
