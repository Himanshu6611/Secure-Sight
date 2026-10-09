"""Investigation persistence and descriptive analytics over authorized records."""
from collections import Counter
import copy
import json
import time
from datetime import datetime, timezone
from flask import current_app, g, has_request_context
from .contracts import project


def capture(result, kind, principal=None):
    store = current_app.extensions.get("dashboard_store")
    principal = principal or (getattr(g, "dashboard_principal", None) if has_request_context() else None)
    if store is None or principal is None or principal["role"] not in {"ADMIN", "ANALYST", "API_CLIENT"}:
        return None
    try:
        record, entities = project(result, kind)
        identity = store.save(principal, record, entities)
        return identity
    except Exception:
        current_app.logger.warning("investigation_store_failed", extra={"phase": "12", "error_code": "INVESTIGATION_STORE_UNAVAILABLE"})
        return None


def analytics(store, principal, filters=None):
    key = (principal["tenant"], json.dumps(filters or {}, sort_keys=True))
    with store.lock:
        entry = store.analytics_cache.get(key)
        if entry and time.monotonic() - entry[0] < 5:
            result = copy.deepcopy(entry[1])
        else:
            result = _analytics(store, principal, filters)
            if len(store.analytics_cache) >= 32:
                store.analytics_cache.clear()
            store.analytics_cache[key] = (time.monotonic(), copy.deepcopy(result))
    jobs = current_app.extensions.get("email_jobs")
    if jobs:
        with jobs.lock:
            result["active_processing_jobs"] = sum(p["tenant"] == principal["tenant"] for p in jobs.dashboard_active.values())
    result["aggregate_cache_seconds"] = 5
    return result


def _analytics(store, principal, filters=None):
    # At most 2000 indexed tenant rows; no raw detection/scoring recomputation.
    listing = store.listing(principal, filters or {}, limit=2000)
    rows = listing["items"]
    verdicts, severities, kinds, days = Counter(), Counter(), Counter(), Counter()
    confidence = Counter({"0–24": 0, "25–49": 0, "50–74": 0, "75–100": 0, "UNKNOWN": 0})
    risk = Counter({"0–19": 0, "20–39": 0, "40–59": 0, "60–79": 0, "80–100": 0, "UNKNOWN": 0})
    today = datetime.now(timezone.utc).date().isoformat()
    partial = failures = high_domains = high_emails = 0
    for r in rows:
        verdicts[r["verdict"]] += 1
        severities[r["severity"] or "UNKNOWN"] += 1
        kinds[r["entity_type"]] += 1
        days[r["created_at"][:10]] += 1
        partial += r["status"] not in {"COMPLETE", "ANALYZED", "OK"} or r["verdict"] == "UNKNOWN"
        failures += r["status"] in {"FAILED", "ANALYSIS_FAILED", "ERROR"}
        high_domains += r["entity_type"] == "URL" and r["severity"] in {"HIGH", "CRITICAL"}
        high_emails += r["entity_type"] == "EMAIL" and r["severity"] in {"HIGH", "CRITICAL"}
        c = r["confidence"]
        confidence["UNKNOWN" if c is None else "0–24" if c < 25 else "25–49" if c < 50 else "50–74" if c < 75 else "75–100"] += 1
        s = r["risk"]
        risk["UNKNOWN" if s is None else "0–19" if s < 20 else "20–39" if s < 40 else "40–59" if s < 60 else "60–79" if s < 80 else "80–100"] += 1
    total = len(rows)
    brands, tlds, bec, auth_failures, redirects, model_versions, feature_versions = (Counter() for _ in range(7))
    qr_phishing = brand_mismatch = missing_models = missing_history = missing_evidence = telemetry_coverage = 0
    with store.lock:
        telemetry_rows = store.db.execute("SELECT investigation,data FROM telemetry WHERE tenant=?", (principal["tenant"],)).fetchall()
        selected = {r["id"]: r for r in rows}
        for item in telemetry_rows:
            if item["investigation"] not in selected:
                continue
            telemetry_coverage += 1
            telemetry = store.decrypt(item["data"])
            for name, counter in (("brands", brands), ("tlds", tlds), ("bec_patterns", bec), ("authentication_failures", auth_failures), ("redirect_patterns", redirects)):
                values = set(telemetry.get(name, []))
                if name == "brands":
                    values -= {"UNAVAILABLE", "UNKNOWN", "NONE", "NOT_APPLICABLE", "MODEL_UNAVAILABLE"}
                counter.update(values)
            if telemetry.get("model_version"):
                model_versions[telemetry["model_version"]] += 1
            if telemetry.get("feature_version"):
                feature_versions[telemetry["feature_version"]] += 1
            qr_phishing += bool(telemetry.get("qr_observed")) and selected[item["investigation"]]["verdict"] == "PHISHING"
            brand_mismatch += bool(telemetry.get("brand_mismatch"))
            missing_models += bool(telemetry.get("model_unavailable"))
            missing_history += bool(telemetry.get("history_unavailable"))
            missing_evidence += telemetry.get("provider_failures", 0)
        # Repeated entities are descriptive, scoped and hashed at rest.
        repeated = store.db.execute("SELECT kind,term,count(DISTINCT investigation) AS n FROM entities WHERE tenant=? AND kind IN ('DOMAIN','HASH','BRAND') GROUP BY kind,term HAVING n>=2 ORDER BY n DESC LIMIT 20", (principal["tenant"],)).fetchall()
        alerts = [{"entity_type": r[0], "indicator_hash": r[1], "investigation_count": r[2], "meaning": "Repeated observation; maliciousness is not inferred"} for r in repeated]
        domain_rows = store.db.execute("SELECT DISTINCT e.investigation,e.term FROM entities e JOIN investigations i ON i.id=e.investigation WHERE e.tenant=? AND e.kind='DOMAIN' AND i.severity IN ('HIGH','CRITICAL')", (principal["tenant"],)).fetchall()
        high_domain_count = len({r["term"] for r in domain_rows if r["investigation"] in selected})
        jobs = current_app.extensions.get("email_jobs")
        if jobs:
            with jobs.lock:
                active_jobs = sum(p["tenant"] == principal["tenant"] for p in jobs.dashboard_active.values())
        else:
            active_jobs = 0
    return {"contract_version": "12.0", "scope": "AUTHORIZED_TENANT", "total_scans": total, "scans_today": days[today],
        "phishing_detections": verdicts["PHISHING"], "suspicious_detections": verdicts["SUSPICIOUS"], "legitimate_candidates": verdicts["LEGITIMATE"],
        "unknown_or_partial": partial, "analysis_failures": failures, "high_risk_url_investigations": high_domains,
        "high_risk_email_investigations": high_emails, "high_risk_domains": high_domain_count, "media_investigations": kinds["MEDIA"], "active_processing_jobs": active_jobs,
        "telemetry_coverage_records": telemetry_coverage, "telemetry_missing_records": total - telemetry_coverage,
        "active_jobs_scope": "CURRENT_PROCESS_ONLY", "brand_mismatch_investigations": brand_mismatch, "deepfake_detections": None,
        "top_observed_brands": dict(brands.most_common(10)), "top_observed_tlds": dict(tlds.most_common(10)), "bec_patterns": dict(bec),
        "authentication_failure_trends": dict(auth_failures), "redirect_patterns": dict(redirects), "qr_bearing_phishing_investigations": qr_phishing,
        "model_unavailable_investigations": missing_models, "limited_history_investigations": missing_history,
        "missing_evidence_observations": missing_evidence, "model_versions": dict(model_versions), "feature_versions": dict(feature_versions),
        "verdict_distribution": dict(verdicts), "severity_distribution": dict(severities), "risk_distribution": dict(risk),
        "confidence_distribution": dict(confidence), "daily_volume": [{"date": d, "scans": n} for d, n in sorted(days.items())],
        "phishing_rate": verdicts["PHISHING"] / total if total else None, "suspicious_rate": verdicts["SUSPICIOUS"] / total if total else None,
        "alerts": alerts, "alerts_scope": "TENANT_ALL_STORED_HISTORY", "recent": rows[:5], "unavailable": ["calibration", "drift", "validated_ground_truth", "external_campaign_history", "deepfake_probability"],
        "limitations": ["Rates describe stored scans, not measured detection accuracy.", "Distribution bins describe backend indexes and do not decide verdicts.", "Shared indicators do not prove a campaign.", "Active job count is local to this process.", "Detailed telemetry charts cover only records with stored telemetry; missing records are counted separately."]}
