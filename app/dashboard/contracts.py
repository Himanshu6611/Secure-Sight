"""Bounded adapters for authoritative Phase 2–11 output. No scoring or inference."""
import copy
import hashlib
import json
import math
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit
from app.behavior.privacy import redact_url
from .store import now
from .types import Investigation

VERSION = "12.0"
MAX_RECORD_BYTES = 1024 * 1024
TYPES = {"OBSERVED", "INFERRED", "MODEL_DERIVED", "EXTERNAL", "MISSING", "CONTRADICTORY"}


def clean(value, depth=0, key=""):
    if depth > 20:
        return "OMITTED_DEPTH_LIMIT"
    if isinstance(value, dict):
        return {str(k)[:128]: clean(v, depth + 1, str(k)) for k, v in list(value.items())[:256]
                if not str(k).startswith("_") and k not in {"raw_email", "raw_html", "password", "token", "feature_vector", "bytes", "content_bytes", "payload"}}
    if isinstance(value, list):
        return [clean(item, depth + 1, key) for item in value[:1024]]
    if isinstance(value, str):
        text = value[:32768]
        if key == "snippet":
            return "PRIVATE_BODY_NOT_RETAINED"
        # Escape at rendering, redact URL credentials/query values at storage.
        return re.sub(r"https?://[^\s<>\"']+", lambda m: redact_url(m.group(0)), text)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value if value is None or isinstance(value, (int, float, bool)) else str(value)[:256]


def phase(source):
    match = re.search(r"phase[_ ](\d+)", str(source), re.I)
    return match.group(1) if match else None


def project(result, kind) -> tuple[Investigation, list[dict]]:
    raw = clean(copy.deepcopy(result))
    if "email_analysis" in raw:
        raw = raw["email_analysis"]
    if kind == "MEDIA" and isinstance(raw.get("media"), dict):
        raw = raw["media"]
    risk = raw.get("risk") or raw.get("assessment") or {}
    if not isinstance(risk, dict):
        risk = {}
    status = raw.get("analysis_status") or raw.get("status") or "UNAVAILABLE"
    subject = raw.get("url") or raw.get("message", {}).get("headers", {}).get("subject") or raw.get("artifact", {}).get("sha256") or "Unavailable subject"
    timestamp = now()
    record = {"contract_version": VERSION, "investigation_id": secrets.token_hex(16), "created_at": timestamp,
              "updated_at": timestamp, "subject": str(subject)[:2048], "entity_type": kind,
              "summary": {"verdict": risk.get("verdict", raw.get("verdict", "UNKNOWN")), "risk_score": risk.get("risk_score"),
                          "severity": risk.get("severity"), "confidence": risk.get("confidence"),
                          "confidence_kind": risk.get("confidence_kind", "UNAVAILABLE"),
                          "assessment_scope": risk.get("assessment_scope", "URL_EVIDENCE" if kind == "URL" else "UNAVAILABLE"),
                          "confidence_calibrated": risk.get("confidence_calibrated", False), "status": status,
                          "analysis_completeness": risk.get("analysis_completeness"), "evidence_coverage": risk.get("evidence_coverage"),
                          "ml_probability": raw.get("ml_probability"), "assessment_version": risk.get("assessment_version"),
                          "scoring_config_sha256": risk.get("scoring_config_sha256")},
              "evidence": [], "explanations": [], "timeline": [], "graph": {"nodes": [], "edges": []},
              "coverage": [], "contradictions": [], "warnings": [], "panels": {}, "analyst_assessment": {"status": "NEW", "tags": [], "feedback": "UNKNOWN", "validated_ground_truth": False},
              "limitations": ["Stored results are private presentation data, not a new assessment.", "Missing probabilities and unavailable intelligence remain unknown.", "No raw email body, original HTML or binary attachment is retained."]}
    entities, known = [], set()
    def entity(kind, value, search=None):
        if value is None or not isinstance(value, (str, int)):
            return
        if kind == "BRAND" and str(value).upper() in {"UNAVAILABLE", "UNKNOWN", "NONE", "NOT_APPLICABLE", "MODEL_UNAVAILABLE"}:
            return
        item = (kind, str(search if search is not None else value).casefold())
        if item not in known and len(entities) < 512:
            known.add(item)
            entities.append({"type": kind, "search": item[1], "value": str(value)[:2048]})
    entity("INVESTIGATION", record["investigation_id"])
    def observe(value, path="", depth=0):
        if depth > 18:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                p = path + "." + key
                if isinstance(child, str):
                    if key in {"domain", "hostname", "registrable_domain", "from_domain", "sender_domain", "reply_to_domain"}:
                        entity("DOMAIN", child)
                    elif key in {"url", "final_url", "analysis_target", "normalized_url", "destination"} and child.startswith(("http://", "https://")):
                        entity("URL", child)
                        entity("DOMAIN", urlsplit(child).hostname)
                    elif key in {"sha256", "email_id", "source_sha256", "artifact_sha256", "message_id_sha256", "payload_sha256", "dhash", "phash", "mailbox_sha256"}:
                        entity("MESSAGE_ID_HASH" if key == "message_id_sha256" else "EMAIL_HASH" if key == "mailbox_sha256" else "HASH", child)
                    elif key in {"brand", "primary_brand", "claimed_brand"}:
                        entity("BRAND", child)
                    elif key in {"ip", "address"} and child != "PRIVATE_REDACTED":
                        entity("IP", child)
                    if key in {"timestamp", "observed_at", "created_at", "creation_date", "updated_date", "expiration_date", "first_seen", "first_seen_at", "ingested_at", "date", "not_before", "not_after"} and len(record["timeline"]) < 256:
                        try:
                            parsed = datetime.fromisoformat(child.replace("Z", "+00:00"))
                            if parsed.tzinfo is not None:
                                record["timeline"].append({"timestamp": parsed.astimezone(timezone.utc).isoformat(), "event": p, "source": value.get("source", path or "backend"), "confidence": value.get("confidence"), "provenance": "BACKEND_FIELD", "claimed": "received" in p or "headers" in p})
                            elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", child):
                                record["timeline"].append({"timestamp": child, "precision": "DATE_ONLY", "event": p, "source": value.get("source", path or "backend"), "confidence": value.get("confidence"), "provenance": "BACKEND_FIELD", "claimed": "received" in p or "headers" in p})
                        except ValueError:
                            pass
                elif isinstance(child, list) and key in {"observed_brands", "display_name", "body"}:
                    for brand_name in child[:32]:
                        if isinstance(brand_name, str):
                            entity("BRAND", brand_name)
                observe(child, p, depth + 1)
        elif isinstance(value, list):
            for i, child in enumerate(value[:256]):
                observe(child, path + f"[{i}]", depth + 1)
    observe(raw)
    visited_destinations = set()
    root_has_graph = bool((raw.get("graph") or raw.get("brand_intelligence", {}).get("evidence_graph", {})).get("nodes"))
    def add_panel(name, data, prefix):
        record["panels"].setdefault(name, []).append({"context": prefix or "root", "data": data})
    def ingest(value, prefix="", version=None):
        if not isinstance(value, dict):
            return
        if value.get("url") and value.get("assessment"):
            snapshot = hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()
            if snapshot in visited_destinations:
                return
            visited_destinations.add(snapshot)
        assessment = value.get("risk") or value.get("assessment") or {}
        version = value.get("email_feature_version") or value.get("media_version") or assessment.get("assessment_version") or version
        for name, key in (("Domain", "domain_intelligence"), ("Domain", "sender_intelligence"), ("Website", "web_intelligence"), ("Redirects", "behavior_intelligence"), ("Brand", "brand_intelligence"), ("Brand", "brand_analysis"), ("Brand", "brands"), ("Email", "message"), ("Authentication", "authentication"), ("Email content", "body_analysis"), ("Attachments", "attachments"), ("Media", "artifact"), ("Media metadata", "metadata"), ("Media quality", "quality"), ("OCR", "ocr"), ("QR", "qr"), ("C2PA", "provenance"), ("Media forensics", "forensics"), ("Media models", "synthetic_media"), ("Campaign", "campaign")):
            if value.get(key) is not None:
                add_panel(name, value[key], prefix)
        brand = value.get("brand_intelligence", {})
        for name, key in (("History", "historical_analysis"), ("Crawl map", "crawl")):
            if key in brand:
                add_panel(name, brand[key], prefix)
        headers = value.get("message", {}).get("headers", {})
        if headers.get("received"):
            add_panel("Received chain", headers["received"], prefix)
        source_rows = []
        if not value.get("email_feature_version") and not value.get("media_version"):
            # Email/media risk may copy a linked assessment; its source evidence is shown once at the destination.
            for key in ("signals", "behavioral_evidence", "brand_evidence"):
                source_rows.extend(assessment.get(key, []))
        source_rows.extend(e for e in value.get("evidence", []) if isinstance(e, dict))
        for i, e in enumerate(source_rows):
            if len(record["evidence"]) >= 1024:
                break
            identity = str(e.get("evidence_id") or e.get("signal_id") or e.get("id") or e.get("indicator") or i)
            source = e.get("source", "phase_10" if value.get("media_version") else "backend")
            source_phase = phase(source) or ("11" if value.get("email_feature_version") else "10" if value.get("media_version") else None)
            source_version = {"2": value.get("feature_schema_version"), "5": value.get("model_version"),
                "8": value.get("behavior_feature_version"), "9": value.get("brand_feature_version"),
                "10": value.get("media_version"), "11": value.get("email_feature_version")}.get(source_phase)
            kind_e = e.get("evidence_type") or ("MISSING" if identity == "media.model_unavailable" or e.get("state") not in {None, "AVAILABLE", "NOT_APPLICABLE"} else "MODEL_DERIVED" if e.get("category") == "ML" else "INFERRED" if e.get("category") in {"BRAND", "CONTENT", "NLP"} else "EXTERNAL" if e.get("category") == "REPUTATION" else "OBSERVED")
            record["evidence"].append({**e, "evidence_id": prefix + identity, "original_evidence_id": identity,
                "category": e.get("category", "MEDIA" if kind == "MEDIA" else "UNKNOWN"), "indicator": e.get("indicator", identity),
                "value": e.get("value"), "severity": e.get("severity"), "confidence": e.get("confidence"),
                "confidence_scale": "0..1 or unavailable", "source": source, "source_version": e.get("source_version", source_version), "context_version": version,
                "phase": source_phase, "timestamp": e.get("timestamp", e.get("observed_at")), "recorded_at": timestamp,
                "evidence_type": kind_e if kind_e in TYPES else "MISSING", "artifact_hash": e.get("source_sha256") or e.get("email_id"),
                "related_entities": e.get("related_entities", [])})
        explanation = value.get("explanation", {})
        seen = set()
        for key in ("reasons", "top_reasons", "positive_signals", "negative_signals", "missing_information", "behavioral_reasons", "brand_reasons"):
            for reason in explanation.get(key, []):
                identity = reason.get("evidence_id") or reason.get("signal_id") or reason.get("reason_id")
                if not identity or identity in seen:
                    continue
                seen.add(identity)
                evidence_ids = [e["evidence_id"] for e in record["evidence"] if e["evidence_id"] == prefix + identity or e["original_evidence_id"] == identity and e["evidence_id"].startswith(prefix)]
                observation = next((e for e in record["evidence"] if e["evidence_id"] in evidence_ids), {})
                record["explanations"].append({**reason, "source": reason.get("source", observation.get("source")),
                    "evidence_type": reason.get("evidence_type", observation.get("evidence_type")), "context": prefix or "root", "evidence_references": evidence_ids,
                    "reference_status": "AVAILABLE" if evidence_ids else "BACKEND_REASON_WITHOUT_EVIDENCE_REFERENCE", "explanation_version": explanation.get("version") or explanation.get("explanation_version")})
        if explanation:
            add_panel("Explanation", explanation, prefix)
        record["contradictions"].extend({"context": prefix or "root", "data": x} for x in assessment.get("contradictions", []) + explanation.get("contradictions", []))
        record["warnings"].extend({"context": prefix or "root", "data": x} for x in value.get("warnings", []) + value.get("errors", []) + assessment.get("warnings", []))
        stages = assessment.get("audit", {}).get("stages", {})
        record["coverage"].extend({"component": prefix + key, "status": status, "source": "PHASE_6_STAGE"} for key, status in stages.items())
        if not stages:
            record["coverage"].append({"component": prefix + "analysis", "status": value.get("analysis_status", value.get("status", "UNAVAILABLE")), "source": "BACKEND_STATUS"})
        graph = {} if prefix and root_has_graph else value.get("graph") or brand.get("evidence_graph") or {}
        existing = {n["id"] for n in record["graph"]["nodes"]}
        for node in graph.get("nodes", [])[:512]:
            if "id" in node and prefix + str(node["id"]) not in existing and len(record["graph"]["nodes"]) < 512:
                record["graph"]["nodes"].append({**node, "id": prefix + str(node["id"]), "provenance": "BACKEND_GRAPH"})
                existing.add(prefix + str(node["id"]))
        for edge in graph.get("edges", [])[:1024]:
            if prefix + str(edge.get("source")) in existing and prefix + str(edge.get("target")) in existing and len(record["graph"]["edges"]) < 1024:
                record["graph"]["edges"].append({**edge, "source": prefix + str(edge["source"]), "target": prefix + str(edge["target"]), "provenance": "BACKEND_GRAPH"})
        for key in ("urls", "linked_analysis", "media", "messages"):
            rows = value.get(key, [])
            if isinstance(rows, list):
                for i, child in enumerate(rows[:3]):
                    if isinstance(child, dict):
                        ingest(child.get("analysis", child), prefix + key + f":{i}:", version)
    ingest(raw)
    record["timeline"].append({"timestamp": timestamp, "event": "Investigation recorded", "source": "phase_12", "confidence": None, "provenance": "STORE_EVENT", "claimed": False})
    record["timeline"].sort(key=lambda e: e["timestamp"])
    record["warnings"] = record["warnings"][:128]
    record["explanations"] = record["explanations"][:256]
    record["contradictions"] = record["contradictions"][:64]
    for evidence in record["evidence"]:
        entity("SOURCE", evidence["source"])
        entity("EVIDENCE_TYPE", evidence["evidence_type"])
    record["telemetry"] = {"brands": sorted({e["value"] for e in entities if e["type"] == "BRAND"}),
        "tlds": sorted({e["value"].rsplit(".", 1)[-1] for e in entities if e["type"] == "DOMAIN" and "." in e["value"]}),
        "bec_patterns": [e["indicator"] for e in record["evidence"] if e["category"] == "BEC"],
        "authentication_failures": [method for panel in record["panels"].get("Authentication", []) for method in ("spf", "dkim", "dmarc", "arc") if panel["data"].get(method, {}).get("result") in {"FAIL", "PERMERROR", "TEMPERROR"}],
        "redirect_patterns": [e["indicator"] for e in record["evidence"] if e["source"] == "phase_8"],
        "qr_observed": any(panel["data"].get("items") for panel in record["panels"].get("QR", [])),
        "brand_mismatch": any("MISMATCH" in e["indicator"] and e["category"] == "BRAND" for e in record["evidence"]),
        "model_unavailable": any("MODEL_UNAVAILABLE" in json.dumps(panel["data"]) for panel in record["panels"].get("Media models", []) + record["panels"].get("Email content", [])),
        "history_unavailable": any(panel["data"].get("status") in {"UNAVAILABLE", "PARTIAL"} for panel in record["panels"].get("History", [])),
        "provider_failures": sum(e["evidence_type"] == "MISSING" for e in record["evidence"]),
        "model_version": raw.get("model_version"), "feature_version": raw.get("feature_schema_version") or raw.get("email_feature_version") or raw.get("media_version")}
    if len(json.dumps(record, allow_nan=False).encode()) > MAX_RECORD_BYTES:
        raise ValueError("INVESTIGATION_RESULT_RESOURCE_LIMIT")
    return record, entities


def query_term(query):
    if "@" in query and not query.startswith(("http://", "https://")):
        return hashlib.sha256(query.encode()).hexdigest()
    if query.startswith("<") and query.endswith(">"):
        return hashlib.sha256(query.encode()).hexdigest()
    if query.startswith(("http://", "https://")):
        return redact_url(query)
    return query.removeprefix("sha256:")
