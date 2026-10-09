"""Analyze observed gateway/Phase 4 outputs only; never fetch or execute pages."""
from urllib.parse import urlsplit
from .config import load_config
from .evidence import indicator, FEATURES, validate_behavior
from .privacy import redact_url
from utils.domain_extraction import extract_domain_components
from utils.url_config import URL_SHORTENERS


def analyze_behavior(initial_url, fetch, static=None, web_features=None):
    config = load_config()
    chain = fetch.get("redirect_chain", [])
    statuses = {"SUCCESS": "ANALYZED", "REDIRECT_LIMIT_EXCEEDED": "REDIRECT_LIMIT", "RESOURCE_LIMIT_EXCEEDED": "RESOURCE_LIMIT",
                "INVALID_URL": "SSRF_BLOCKED", "SSRF_BLOCKED": "SSRF_BLOCKED", "DNS_FAILED": "DNS_FAILED", "TIMEOUT": "TIMEOUT", "REDIRECT_LOOP": "REDIRECT_LOOP"}
    status = statuses.get(fetch.get("status"), "FETCH_FAILED")
    static = static or {}
    destinations = static.get("destinations", [])
    records = []
    def add(code, observed=1, confidence=.99, kind="OBSERVED"):
        if observed and not any(r["indicator"] == code for r in records):
            records.append(indicator(code, int(observed), confidence, kind))
    crossed = sum(h.get("same_domain") is False for h in chain)
    domains = {extract_domain_components(initial_url)["normalized_registrable_domain"]} if fetch.get("status_code") is not None else set()
    domains.update(h["destination_domain"] for h in chain if h.get("followed") and h.get("destination_domain"))
    initial, final = urlsplit(initial_url), urlsplit(fetch.get("final_url") or initial_url)
    final_reached = fetch.get("status") == "SUCCESS"
    comparison = {
        "scheme_changed": initial.scheme != final.scheme, "domain_changed": initial.hostname != final.hostname,
        "registrable_domain_changed": extract_domain_components(initial_url)["normalized_registrable_domain"] != extract_domain_components(final.geturl())["normalized_registrable_domain"],
        "path_changed": initial.path != final.path, "query_changed": initial.query != final.query,
        "port_changed": (initial.port or (443 if initial.scheme == "https" else 80)) != (final.port or (443 if final.scheme == "https" else 80))}
    up, down = int(any(h.get("http_to_https") for h in chain)), int(any(h.get("https_to_http") for h in chain))
    loop = int(fetch.get("redirect_loop_detected", False))
    shortener = int(initial.hostname in URL_SHORTENERS)
    js = int(any(d["redirect_type"] == "JAVASCRIPT_PATTERN" for d in destinations))
    meta = int(any(d["redirect_type"] == "META_REFRESH" for d in destinations))
    add("BEHAVIOR_CROSS_DOMAIN", crossed)
    add("BEHAVIOR_REDIRECT_LOOP", loop)
    add("BEHAVIOR_DUPLICATE_DESTINATION", loop)
    add("BEHAVIOR_EXCESSIVE_REDIRECTS", len(chain) if len(chain) >= config["excessive_redirect_threshold"] else 0)
    add("BEHAVIOR_DOMAIN_HOPPING", crossed if crossed >= config["domain_hopping_threshold"] else 0)
    add("BEHAVIOR_SHORTENER", shortener)
    add("BEHAVIOR_HTTP_TO_HTTPS", up)
    add("BEHAVIOR_HTTPS_TO_HTTP", down)
    add("BEHAVIOR_PORT_CHANGE", any(h.get("port_changed") and not (h.get("http_to_https") or h.get("https_to_http")) for h in chain))
    add("BEHAVIOR_META_REFRESH", meta, .95)
    add("BEHAVIOR_JAVASCRIPT_REDIRECT", js, .6, "INFERRED")
    add("BEHAVIOR_FINAL_DOMAIN_CHANGE", final_reached and comparison["registrable_domain_changed"])
    add("BEHAVIOR_STATIC_DESTINATION_BLOCKED", any(d["status"] == "DESTINATION_BLOCKED" for d in destinations), .95)
    add("BEHAVIOR_NEW_WINDOW_PATTERN", static.get("window_open_pattern_count", 0) or static.get("target_blank_count", 0), .6, "INFERRED")
    add("BEHAVIOR_CHALLENGE_PATTERN", static.get("challenge_pattern_detected", False), .5, "INFERRED")
    add("BEHAVIOR_OBFUSCATED_SCRIPT", (web_features or {}).get("obfuscated_script_count", 0), .6, "INFERRED")
    features = {"redirect_count": len(chain), "unique_redirect_domains": len(domains), "domain_transition_count": crossed,
        "cross_domain_redirect_ratio": crossed/len(chain) if chain else 0., "redirect_loop_detected": loop,
        "http_to_https": up, "https_to_http": down, "shortener_detected": shortener,
        "js_redirect_detected": js if static.get("status") == "ANALYZED" else None,
        "meta_refresh_detected": meta if static.get("status") == "ANALYZED" else None,
        "final_domain_changed": int(comparison["registrable_domain_changed"]) if final_reached else None}
    if status == "ANALYZED" and static.get("status") != "ANALYZED":
        status = "PARTIAL"
    if static.get("destination_limit_reached"):
        status = "PARTIAL"
    seconds = fetch.get("elapsed_ms", 0)/1000
    result = {"status": status, "feature_version": "8.0.0", "initial_url": redact_url(initial_url),
        "final_url": redact_url(final.geturl()) if final_reached else None,
        "last_attempted_url": redact_url(final.geturl()), "final_destination_reached": final_reached,
        "chain": chain, "redirect_count": len(chain), "initial_final_comparison": comparison,
        "unique_registrable_domains": len(domains), "domain_transition_count": crossed,
        "domain_transition_rate_per_second": round(crossed/seconds, 4) if seconds else None,
        "rapid_domain_hopping": crossed >= config["domain_hopping_threshold"] and 0 < seconds <= config["rapid_domain_hopping_window_seconds"],
        "static_behavior": static, "features": features, "indicators": records,
        "resources": {"request_count": fetch.get("request_count", 0), "response_bytes": fetch.get("response_bytes", 0),
            "unique_ip_count": fetch.get("unique_ip_count", 0), "elapsed_ms": fetch.get("elapsed_ms", 0),
            "cpu_ms": None, "memory_bytes": None},
        "dynamic_analysis": {"status": "NOT_RUN", "execution_mode": "NOT_EXECUTED", "browser_isolation": "NOT_IMPLEMENTED"},
        "timeline": [{"timestamp_ms": h["timestamp_ms"], "type": "HTTP_REDIRECT", "status": h["status_code"]} for h in chain]}
    return validate_behavior(result)
