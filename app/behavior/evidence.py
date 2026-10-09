"""Known behavior evidence IDs, bounded schema and centralized plain-text wording."""
import json
import math
from pathlib import Path
from app.risk.config import unique_object

STATUSES = {"NOT_RUN", "ANALYZED", "PARTIAL", "TIMEOUT", "SSRF_BLOCKED", "REDIRECT_LIMIT", "RESOURCE_LIMIT", "FETCH_FAILED", "DNS_FAILED", "BROWSER_FAILED", "ANALYSIS_FAILED", "REDIRECT_LOOP"}
FEATURES = {"redirect_count", "unique_redirect_domains", "domain_transition_count", "cross_domain_redirect_ratio", "redirect_loop_detected",
    "http_to_https", "https_to_http", "shortener_detected", "js_redirect_detected", "meta_refresh_detected", "final_domain_changed"}
KNOWN_IDS = {"BEHAVIOR_" + suffix for suffix in ("CROSS_DOMAIN", "REDIRECT_LOOP", "DUPLICATE_DESTINATION", "EXCESSIVE_REDIRECTS", "DOMAIN_HOPPING",
    "SHORTENER", "HTTP_TO_HTTPS", "HTTPS_TO_HTTP", "PORT_CHANGE", "META_REFRESH", "JAVASCRIPT_REDIRECT", "OBFUSCATED_SCRIPT",
    "FINAL_DOMAIN_CHANGE", "SUSPICIOUS_FINAL_DESTINATION", "CHALLENGE_PATTERN", "NEW_WINDOW_PATTERN", "STATIC_DESTINATION_BLOCKED")}


def load_reasons():
    path = Path(__file__).resolve().parents[2] / "config" / "behavior_reasons.json"
    raw = path.read_bytes()
    if len(raw) > 16384:
        raise ValueError("Behavior reasons exceed limit")
    registry = json.loads(raw, object_pairs_hook=unique_object)
    if set(registry) != {"version", "indicators"} or registry["version"] != "8.0.0" or set(registry["indicators"]) != KNOWN_IDS:
        raise ValueError("Invalid behavior reason registry")
    for key, entry in registry["indicators"].items():
        if not key.startswith("BEHAVIOR_") or set(entry) != {"category", "severity", "title", "description"}:
            raise ValueError("Invalid behavior reason")
        if entry["category"] not in {"REDIRECT", "BEHAVIORAL"} or entry["severity"] not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Invalid behavior reason classification")
        if any(not isinstance(entry[field], str) or not entry[field] or len(entry[field]) > 400 or any(c in entry[field] for c in "<>\x00") for field in ("title", "description")):
            raise ValueError("Unsafe behavior wording")
    return registry


def indicator(code, value=1, confidence=.99, evidence_type="OBSERVED"):
    entry = load_reasons()["indicators"][code]
    return {"indicator": code, **entry, "value": value, "confidence": confidence,
            "source": "phase_8", "evidence_type": evidence_type}


def validate_behavior(value):
    if not isinstance(value, dict) or value.get("feature_version") != "8.0.0" or value.get("status") not in STATUSES:
        raise ValueError("Invalid behavior result")
    features = value.get("features")
    if not isinstance(features, dict) or set(features) != FEATURES:
        raise ValueError("Invalid behavior feature schema")
    for key, observed in features.items():
        if observed is None:
            if value["status"] == "ANALYZED":
                raise ValueError("Successful behavior lacks observations")
            continue
        if type(observed) not in (int, float) or not math.isfinite(observed) or not 0 <= observed <= (1 if key.endswith("detected") or key in {"http_to_https", "https_to_http", "final_domain_changed", "cross_domain_redirect_ratio"} else 64):
            raise ValueError("Invalid behavior feature value")
    records = value.get("indicators")
    if not isinstance(records, list) or len(records) > 32:
        raise ValueError("Invalid behavior indicators")
    known = load_reasons()["indicators"]
    for record in records:
        if not isinstance(record, dict) or record.get("indicator") not in known or record.get("source") != "phase_8":
            raise ValueError("Invalid behavior provenance")
        if record.get("category") != known[record["indicator"]]["category"] or record.get("severity") != known[record["indicator"]]["severity"] or record.get("evidence_type") not in {"OBSERVED", "INFERRED"}:
            raise ValueError("Invalid behavior classification")
        for field, high in (("confidence", 1), ("value", 10000)):
            number = record.get(field)
            if type(number) not in (int, float) or not math.isfinite(number) or not 0 <= number <= high:
                raise ValueError("Invalid behavioral numeric evidence")
        related = {"BEHAVIOR_CROSS_DOMAIN":"domain_transition_count", "BEHAVIOR_REDIRECT_LOOP":"redirect_loop_detected",
            "BEHAVIOR_DUPLICATE_DESTINATION":"redirect_loop_detected", "BEHAVIOR_SHORTENER":"shortener_detected",
            "BEHAVIOR_HTTP_TO_HTTPS":"http_to_https", "BEHAVIOR_HTTPS_TO_HTTP":"https_to_http",
            "BEHAVIOR_META_REFRESH":"meta_refresh_detected", "BEHAVIOR_JAVASCRIPT_REDIRECT":"js_redirect_detected",
            "BEHAVIOR_FINAL_DOMAIN_CHANGE":"final_domain_changed"}
        field = related.get(record["indicator"])
        if field and (features[field] is None or features[field] <= 0 or record["value"] > features[field]):
            raise ValueError("Behavior indicator lacks matching observation")
        if record["indicator"] == "BEHAVIOR_SUSPICIOUS_FINAL_DESTINATION":
            raise ValueError("Destination correlation belongs to Phase 6")
    return value
