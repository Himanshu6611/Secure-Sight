"""Correlated brand/domain/history graph from actual bounded observations."""
from datetime import datetime, timezone
from urllib.parse import urlsplit
from app.brand.config import load_registry
from app.brand.similarity import compare, skeleton
from app.brand.history import analyze_history
from app.brand.crawl import crawl_site
from utils.domain_extraction import extract_domain_components

EVIDENCE_REASONS = {
    "BRAND_MULTI_SOURCE_CLAIM": ("BRAND", "Brand appears in multiple page fields", "Registry brand names were observed in multiple fields of the same page. These fields are correlated evidence."),
    "OFFICIAL_DOMAIN_MATCH": ("BRAND", "Known official domain matched", "The final hostname matches the curated brand registry. This does not prove the page is safe."),
    "LOOKALIKE_DOMAIN": ("DOMAIN", "Brand name lookalike", "A bounded domain comparison found a spelling or confusable pattern. Similarity alone does not prove impersonation."),
    "DOMAIN_BRAND_MISMATCH": ("BRAND", "Page claim and domain differ", "The claimed brand does not match a known official domain. Registry gaps and third party services can explain this."),
    "HISTORICAL_CONTENT_CHANGED": ("HISTORICAL", "Page changed since an earlier observation", "Stored fingerprints differ from an earlier scan. Redesigns and routine updates can cause changes."),
    "HISTORICAL_REPURPOSING_CONTEXT": ("HISTORICAL", "Brand and credential forms changed", "An older domain has changed brand claims and credential form counts since an earlier scan. Ownership changes and compromise are unconfirmed."),
    "HISTORY_LIMITED": ("HISTORICAL", "Historical coverage is limited", "Only bounded observations from this running process are available. Archive, passive DNS, certificate and ownership history are unavailable."),
    "EMAIL_BRAND_DOMAIN_DIFFERENCE": ("BRAND", "Email domain and page brand differ", "Supplied sender or reply-to domain does not match the detected brand registry. Sender authentication was not verified.")
}


def domain_match(host, brand):
    for official in brand["official_domains"]:
        if host == official:
            return "EXACT_MATCH" if official == brand["primary_domain"] else "KNOWN_OFFICIAL_DOMAIN"
        if host.endswith("." + official):
            return "OFFICIAL_SUBDOMAIN"
    return None


def validate_email_context(value):
    from app.security.urls import validate_url
    if value is None:
        return None
    if not isinstance(value, dict) or not value or set(value)-{"sender_domain", "reply_to_domain", "claimed_brand"}:
        raise ValueError("Invalid email correlation context")
    result = {}
    for key in ("sender_domain", "reply_to_domain"):
        if key in value:
            domain = value[key]
            if not isinstance(domain, str) or len(domain) > 253 or any(c in domain for c in "/:@?#"):
                raise ValueError("Invalid email domain")
            result[key] = urlsplit(validate_url("https://" + domain)).hostname
    if "claimed_brand" in value:
        if not isinstance(value["claimed_brand"], str) or value["claimed_brand"] not in {b["id"] for b in load_registry()["brands"]}:
            raise ValueError("Unknown email brand")
        result["claimed_brand"] = value["claimed_brand"]
    return result


def analyze_brand(url, web, domain, original_url=None, email_context=None, enable_crawl=True, store=None):
    registry = load_registry()
    now = datetime.now(timezone.utc).isoformat()
    components = extract_domain_components(url)
    host = components["normalized_hostname"]
    try:
        unicode_host = host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        unicode_host = host
    # Original input is represented by its hostname only; raw path/query never leave this stage.
    original_host = urlsplit(original_url if original_url and "://" in original_url else "https://" + (original_url or host)).hostname or host
    inventory = web.get("_brand_inventory")
    base = dict(feature_version="9.0.0", registry_version=registry["version"], registry_updated_at=registry["updated_at"],
        status="UNAVAILABLE", detected_brands=[], primary_brand=None, domain_match="UNKNOWN",
        domain_representation=dict(original_hostname=original_host[:253], unicode_hostname=unicode_host, normalized_hostname=host,
            registrable_domain=components["normalized_registrable_domain"], punycode_hostname=host, confusable_skeleton=skeleton(unicode_host)),
        typosquatting=[], homoglyph=dict(detected=False, mapping_scope="LIMITED_COMMON_CYRILLIC_GREEK"),
        historical_analysis=dict(status="UNAVAILABLE", reason="PAGE_UNAVAILABLE"), website_age=dict(status="UNAVAILABLE", first_seen=None, created_at=None),
        page_age=dict(status="UNAVAILABLE", first_seen=None, created_at=None), domain_timeline=[],
        evidence=[], evidence_graph=dict(nodes=[], edges=[]), features=dict(corroborated_brand_mismatch=None),
        crawl=dict(status="UNAVAILABLE", pages=[], stop_reason="PAGE_UNAVAILABLE"),
        email_correlation=dict(status="NOT_APPLICABLE" if email_context is None else "UNAVAILABLE"),
        retrieved_at=now, used_by_serving_model=False)
    base["content_consistency"] = dict(canonical_domain_mismatch=web.get("html_features", {}).get("canonical_domain_mismatch"),
        favicon_domain_mismatch=web.get("html_features", {}).get("favicon_domain_mismatch"),
        logo_visual_comparison="UNAVAILABLE", ocr_comparison="UNAVAILABLE", contact_identity_verification="UNAVAILABLE",
        interpretation="External canonical/favicon resources and missing legal text do not prove impersonation.")
    if web.get("status") != "ANALYZED" or not isinstance(inventory, dict):
        return base
    claims = inventory["brand_claims"]
    base["page_inventory"] = {k:v for k,v in inventory.items() if k != "_links"}
    base["page_inventory"]["html_features"] = web.get("html_features", {})
    brands = {b["id"]: b for b in registry["brands"]}
    official_brand = next((b for b in registry["brands"] if domain_match(host, b)), None)
    strongest = sorted(claims, key=lambda c: (-c["source_count"], c["brand_id"]))
    primary = brands[strongest[0]["brand_id"]] if strongest else official_brand
    if len(strongest) > 1 and strongest[0]["source_count"] == strongest[1]["source_count"]:
        primary = official_brand if official_brand and any(c["brand_id"] == official_brand["id"] for c in strongest) else None
    primary_claim = next((c for c in claims if primary and c["brand_id"] == primary["id"]), None)
    base["content_consistency"]["declared_domain_mismatch_count"] = sum(d != components["normalized_registrable_domain"] for d in inventory.get("declared_domains", []))
    match = domain_match(host, primary) if primary else None
    label = components["normalized_registrable_domain"].split(".", 1)[0]
    unicode_label = unicode_host.rsplit(".", max(1, len(host.split("."))-1))[0] if "." in unicode_host else unicode_host
    # Compare registrable label, excluding unrelated subdomain text.
    try:
        unicode_label = label.encode("ascii").decode("idna")
    except UnicodeError:
        unicode_label = label
    for brand in registry["brands"]:
        if domain_match(host, brand):
            continue
        for alias in brand["aliases"]:
            comparison = compare(skeleton(unicode_label), alias.casefold())
            confusable = unicode_label != skeleton(unicode_label) and skeleton(unicode_label) == alias.casefold()
            if comparison["patterns"] or confusable or (0 < comparison["levenshtein"] <= 2):
                if len(base["typosquatting"]) < 32:
                    base["typosquatting"].append(dict(brand_id=brand["id"], **comparison, confusable=confusable))
                else:
                    base["typosquatting_truncated"] = True
    matching_typo = next((t for t in base["typosquatting"] if primary and t["brand_id"] == primary["id"]), None)
    strong_typo = bool(matching_typo and (matching_typo["confusable"] or 0 < matching_typo["levenshtein"] <= 2 or "TRANSPOSITION" in matching_typo["patterns"]))
    if primary and not match:
        match = "LOOKALIKE" if matching_typo else "MISMATCH" if primary_claim and primary_claim["source_count"] >= 2 else "POSSIBLE_MATCH"
    identity_sources = {"title", "headings", "form_labels", "logo_alt", "structured_data"}
    strong_claim = bool(primary_claim and primary_claim["source_count"] >= 2 and identity_sources.intersection(primary_claim["sources"]))
    credentials = bool(web.get("html_features", {}).get("password_input_count"))
    external_nonofficial = bool(primary and any(f.get("is_credential_form") and f.get("is_external") and
        not domain_match(urlsplit(f.get("resolved_action", "")).hostname or "", primary) for f in web.get("forms", [])))
    official_auth_destination = bool(primary and any(f.get("is_credential_form") and domain_match(
        urlsplit(f.get("resolved_action", "")).hostname or "", primary) for f in web.get("forms", [])))
    mismatch = bool(primary and not domain_match(host, primary) and strong_claim and credentials and
        (external_nonofficial or (strong_typo and not official_auth_destination)))
    base.update(status="PARTIAL", detected_brands=[dict(**c, canonical_name=brands[c["brand_id"]]["canonical_name"]) for c in claims],
        primary_brand=primary["id"] if primary else None, domain_match=match or "UNKNOWN",
        features=dict(corroborated_brand_mismatch=int(mismatch), credential_page=int(credentials),
            multi_source_claim=int(strong_claim), strong_lookalike=int(strong_typo), external_nonofficial_credentials=int(external_nonofficial),
            known_official_match=int(bool(primary and domain_match(host, primary))),
            official_auth_destination=int(official_auth_destination)))
    base["homoglyph"]["detected"] = any(t["confusable"] for t in base["typosquatting"])
    crawl = crawl_site(url, inventory, web.get("fetch_summary", {})) if enable_crawl else dict(status="NOT_RUN", pages=[], _children=[])
    children = crawl.pop("_children", [])
    base["crawl"] = crawl
    # Additional pages inform inspection coverage; their correlated claims never multiply root risk.
    base["inspected_brand_ids"] = sorted({c["brand_id"] for c in claims} | {c["brand_id"] for p in children for c in p["inventory"]["brand_claims"]})
    history = analyze_history(url, inventory, web, domain, [c["brand_id"] for c in claims], store=store)
    base.update(historical_analysis=history, website_age=history["website_age"], page_age=history["page_age"], domain_timeline=history["timeline"])
    for child in children:
        child_history = analyze_history(child["url"], child["inventory"], child, domain,
            [c["brand_id"] for c in child["inventory"]["brand_claims"]], store=store)
        page = base["crawl"]["pages"][child["_page_index"]]
        page.update(page_age=child_history["page_age"], website_age=child_history["website_age"],
            historical_changes=child_history["changes"])
    def evidence(code, value):
        category = EVIDENCE_REASONS[code][0]
        base["evidence"].append(dict(indicator=code, category=category, source="phase_9", value=value,
            confidence=.5, observed_at=now, independence_group="STATIC_PAGE" if category != "HISTORICAL" else "INTERNAL_HISTORY"))
    if strong_claim:
        evidence("BRAND_MULTI_SOURCE_CLAIM", primary_claim["source_count"])
    if primary and domain_match(host, primary):
        evidence("OFFICIAL_DOMAIN_MATCH", 1)
    elif primary_claim:
        evidence("DOMAIN_BRAND_MISMATCH", 1)
    if base["typosquatting"]:
        evidence("LOOKALIKE_DOMAIN", len(base["typosquatting"]))
    if history["changes"]:
        evidence("HISTORICAL_CONTENT_CHANGED", len(history["changes"]))
    if history["repurposing_context"]:
        evidence("HISTORICAL_REPURPOSING_CONTEXT", 1)
    evidence("HISTORY_LIMITED", 1)
    if email_context:
        normalized = validate_email_context(email_context)
        differences = sum(not domain_match(normalized[k], primary) for k in ("sender_domain", "reply_to_domain") if k in normalized) if primary else 0
        base["email_correlation"] = dict(status="PARTIAL", domain_differences=differences,
            claimed_brand_consistent=normalized.get("claimed_brand") == primary["id"] if primary and normalized.get("claimed_brand") else None,
            authentication_status="UNVERIFIED", embedded_urls_status="ONLY_SUBMITTED_URL_ASSESSED")
        if differences:
            evidence("EMAIL_BRAND_DOMAIN_DIFFERENCE", differences)
    nodes = [dict(id="domain", type="DOMAIN", value=components["normalized_registrable_domain"]),
        dict(id="page", type="PAGE", value="REDACTED_FINAL_PAGE")]
    edges = [dict(source="page", target="domain", relationship="HOSTED_ON")]
    for claim in claims:
        nodes.append(dict(id=claim["brand_id"], type="BRAND", value=brands[claim["brand_id"]]["canonical_name"]))
        edges.append(dict(source="page", target=claim["brand_id"], relationship="CLAIMS_BRAND", source_fields=claim["sources"], independence_group="STATIC_PAGE"))
    for i, event in enumerate(history["timeline"]):
        identity = "event_" + str(i)
        nodes.append(dict(id=identity, type="HISTORICAL", value=event["event"], observed_at=event["date"], provenance=event["source"]))
        edges.append(dict(source=identity, target="domain" if event["event"] == "DOMAIN_REGISTRATION" else "page", relationship=event["event_type"]))
    base["evidence_graph"] = dict(nodes=nodes, edges=edges)
    return base
