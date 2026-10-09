"""Bounded email orchestration reusing Phase 2–10 workers and services."""
import base64
import hashlib
import io
import json
import re
import time
from urllib.parse import urlsplit
from flask import current_app
from werkzeug.datastructures import FileStorage
from app.media.worker import run, run_linked
from app.media.intake import MediaError
from app.security.urls import validate_url, InvalidURL
from app.brand.analyzer import domain_match
from app.brand.similarity import skeleton
from .parser import EmailError, MAX_EMAIL_BYTES
from .headers import relationship
from .evidence import build

MAX_EMAIL_DESTINATION_ANALYSES = 5
MIN_DESTINATION_BUDGET_SECONDS = 15
DESTINATION_RESERVED_SECONDS = 10


def analyze(raw, budget_seconds=90, progress=None):
    started = time.monotonic()
    if not isinstance(raw, bytes) or not raw.strip() or len(raw) > MAX_EMAIL_BYTES:
        raise EmailError("INVALID_EMAIL" if not raw else "EMAIL_RESOURCE_LIMIT", 413 if raw else 400)
    deadline = started + budget_seconds
    timings, states, errors = {}, [], []
    def stage(name):
        states.append(name)
        if progress:
            progress(name)
    stage("PARSING")
    before = time.monotonic()
    try:
        parsed = run(raw, {"mime": "--email"}, "eng", wall_seconds=min(15, budget_seconds), output_limit=2 * 1024 * 1024)
    except MediaError as exc:
        raise EmailError(exc.code, exc.status) from None
    timings["parse_auth_attachment_ms"] = round((time.monotonic() - before) * 1000, 2)
    stage("AUTH_ANALYSIS")
    body = parsed.pop("body_analysis")
    auth = parsed.pop("authentication")
    attachments = parsed.pop("attachments")
    headers = parsed["headers"]
    text = body.pop("_text")
    registry = current_app.extensions["brand_registry"]
    def claims(value):
        value = skeleton(value)
        return [b["id"] for b in registry["brands"] if any(re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", value, re.I) for alias in b["aliases"])]
    displays = " ".join(box["display_name"] for box in headers["identities"]["from"])
    display_brands, body_brands = claims(displays), claims(text)
    lookup = {b["id"]: b for b in registry["brands"]}
    spoofed = [brand for brand in display_brands if headers["from_domain"] and not domain_match(headers["from_domain"], lookup[brand])]
    claimed = display_brands[0] if len(display_brands) == 1 else body_brands[0] if len(body_brands) == 1 else None
    context = {}
    if headers["from_domain"]:
        context["sender_domain"] = headers["from_domain"]
    reply = headers["identities"]["reply-to"]
    if len(reply) == 1 and reply[0]["domain"]:
        context["reply_to_domain"] = reply[0]["domain"]
    if claimed:
        context["claimed_brand"] = claimed
    context = context or None
    sender = {"status": "UNAVAILABLE", "reason": "SENDER_IDENTITY_UNAVAILABLE", "history_status": "UNAVAILABLE", "asn_status": "UNAVAILABLE"}
    stage("SENDER_ANALYSIS")
    before = time.monotonic()
    if headers["from_domain"] and deadline - time.monotonic() > 16:
        try:
            sender = run(json.dumps({"url": "https://" + headers["from_domain"]}).encode(), {"mime": "--domain"}, "eng", wall_seconds=15)
            sender.update(identity_authenticated=False, history_status="UNAVAILABLE", asn_status="UNAVAILABLE")
        except MediaError as exc:
            errors.append({"code": "SENDER_" + exc.code})
    elif headers["from_domain"]:
        errors.append({"code": "SENDER_BUDGET_EXHAUSTED"})
    timings["sender_ms"] = round((time.monotonic() - before) * 1000, 2)
    urls, cache = [], {}
    def destination(value, email_context=None, config=None, source="MEDIA"):
        normalized = validate_url(value)
        # Fragments do not cause distinct HTTP requests; retain query semantics.
        normalized = normalized.split("#", 1)[0]
        if normalized in cache:
            for row in urls:
                if row["identity"] == normalized:
                    row["sources"] = sorted(set(row["sources"] + [source]))
            return cache[normalized]
        remaining = deadline - time.monotonic()
        if len(cache) >= MAX_EMAIL_DESTINATION_ANALYSES or remaining < MIN_DESTINATION_BUDGET_SECONDS:
            raise MediaError("EMAIL_URL_BUDGET_LIMIT", 422)
        stage("WEBSITE_ANALYSIS")
        before = time.monotonic()
        # Reserve the destination even on failure; no retry or duplicate spending.
        cache[normalized] = {"status": "ANALYSIS_FAILED"}
        try:
            scan = run_linked(normalized, context, current_app.config,
                min(20, max(5, int(remaining - DESTINATION_RESERVED_SECONDS))))
            cache[normalized] = scan
        except MediaError as exc:
            errors.append({"code": "URL_" + exc.code})
            scan = cache[normalized]
        from app.behavior.privacy import redact_url
        urls.append({"identity": normalized, "url": redact_url(normalized), "sources": [source], "analysis": scan})
        timings["website_ms"] = round(timings.get("website_ms", 0) + (time.monotonic() - before) * 1000, 2)
        return scan
    stage("URL_ANALYSIS")
    candidates = body.pop("_urls")
    for attachment in attachments:
        candidates.extend({"value": value, "source": "ATTACHMENT"} for value in attachment.pop("_urls"))
    inventory = []
    from app.behavior.privacy import redact_url
    for candidate in candidates:
        entry = {"source": candidate["source"], "url_sha256": hashlib.sha256(candidate["value"].encode()).hexdigest(), "status": "NOT_ANALYZED_RESOURCE_LIMIT"}
        try:
            scan = destination(candidate["value"], source=candidate["source"])
            entry.update(url=redact_url(validate_url(candidate["value"])), status="ANALYSIS_FAILED" if scan.get("status") == "ANALYSIS_FAILED" else "ANALYZED")
        except InvalidURL:
            entry["status"] = "BLOCKED"
            errors.append({"code": "EXTRACTED_URL_BLOCKED"})
        except MediaError as exc:
            errors.append({"code": exc.code})
        inventory.append(entry)
    stage("MEDIA_ANALYSIS")
    media = []
    before = time.monotonic()
    for attachment in attachments:
        data = attachment.pop("_data", None)
        if data is None:
            continue
        if len(media) >= 1 or deadline - time.monotonic() < 16:
            attachment["media_status"] = "RESOURCE_LIMIT"
            errors.append({"code": "EMAIL_MEDIA_BUDGET_LIMIT"})
            continue
        try:
            from app.media.service import analyze as analyze_media
            blob = FileStorage(stream=io.BytesIO(base64.b64decode(data, validate=True)), filename=attachment["filename"], content_type=attachment["mime"])
            result = analyze_media(blob, email_context=context, url_analyzer=destination)
            attachment["media_status"] = result["analysis_status"]
            media.append(result)
        except (MediaError, ValueError, InvalidURL) as exc:
            attachment["media_status"] = "ANALYSIS_FAILED"
            errors.append({"code": "MEDIA_" + str(getattr(exc, "code", "ANALYSIS_FAILED"))})
    timings["media_ms"] = round((time.monotonic() - before) * 1000, 2)
    stage("CORRELATION")
    result = {"email_feature_version": "11.0", "analysis_status": "PARTIAL", "message": parsed,
        "authentication": auth, "sender_intelligence": sender, "body_analysis": body, "urls": urls,
        "attachments": attachments, "media": media, "url_inventory": inventory[:256],
        "brands": {"registry_version": registry["version"], "display_name": display_brands, "body": body_brands,
            "claimed_brand": claimed, "display_name_impersonation": spoofed, "claims_authenticated": False},
        "campaign": {"status": "NOT_APPLICABLE", "scope": "SINGLE_MESSAGE_NO_CROSS_USER_STORE"},
        "correlations": [], "errors": list({e["code"]: e for e in errors}.values())[:32], "timings": timings}
    for item in media:
        result["correlations"].append({"relationship": "EMAIL_ATTACHMENT_MEDIA", "sha256": item["artifact"]["sha256"], "brands": item["brand_analysis"]["observed_brands"]})
    for item in urls:
        result["correlations"].append({"relationship": "EMAIL_DESTINATION", "hostname": urlsplit(item["identity"]).hostname,
            "sender_relationship": relationship(headers["from_domain"], urlsplit(item["identity"]).hostname),
            "sources": item["sources"]})
    result["evidence"] = build(result)
    stage("SCORING")
    result["risk"] = current_app.extensions["risk_engine"].assess_email(result)
    result["explanation"] = current_app.extensions["explanation_engine"].explain_email(result)
    result["confidence"] = {"authentication": None, "sender": None, "media": None, "cross_modal": None,
        "url": [item["analysis"].get("confidence") for item in urls], "website": [item["analysis"].get("confidence") for item in urls],
        "overall": result["risk"]["confidence"], "calibrated": False}
    from .graph import build_graph
    result["graph"] = build_graph(result)
    for item in urls:
        item.pop("identity")
    result["timings"]["total_ms"] = round((time.monotonic() - started) * 1000, 2)
    result["states"] = states + ["PARTIAL"]
    current_app.logger.info("email_analysis_completed", extra={"phase": "11", "status": "PARTIAL",
        "duration_ms": result["timings"]["total_ms"], "verdict": result["risk"]["verdict"], "error_code": None})
    return result


def analyze_batch(messages, progress=None):
    if not isinstance(messages, list) or not 1 <= len(messages) <= 3 or any(not isinstance(m, bytes) or not m.strip() for m in messages) or sum(map(len, messages)) > MAX_EMAIL_BYTES:
        raise EmailError("INVALID_EMAIL_BATCH")
    deadline = time.monotonic() + 90
    results = []
    for message in messages:
        remaining = deadline - time.monotonic()
        if remaining < 16:
            raise EmailError("EMAIL_BATCH_RESOURCE_LIMIT", 422)
        results.append(analyze(message, budget_seconds=remaining, progress=progress))
    from .campaign import correlate
    return {"email_feature_version": "11.0", "analysis_status": "PARTIAL", "messages": results,
            "campaign": correlate(results), "risk": current_app.extensions["risk_engine"].assess_email_batch(results)}
