# utils/domain_intelligence.py
"""
utils/domain_intelligence.py
-----------------------------
Unified Domain & Reputation Intelligence Service for SecureSight Phase 3.
Orchestrates domain extraction, DNS, TLS, WHOIS registration, IP classification, and multi-provider reputation lookup.
Returns standardized feature version 3.0 intelligence structure with explainable indicators and evidence provenance.
"""

from typing import Dict, List, Any
from utils.domain_extraction import extract_domain_components
from utils.dns_intelligence import resolve_dns
from utils.tls_intelligence import analyze_tls_certificate
from utils.registration_intelligence import get_domain_registration
from utils.reputation_providers import MultiProviderAggregator, LocalBlacklistProvider
from utils.domain_cache import DOMAIN_INTELLIGENCE_CACHE


def analyze_domain_intelligence(url: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Perform unified domain intelligence analysis for a URL string.

    Returns:
        Dict containing:
            - feature_version: "3.0"
            - domain_components: dict
            - dns: dict
            - tls: dict
            - registration: dict
            - reputation: dict
            - domain_features: dict (numeric/boolean flags for ML ensemble)
            - indicators: List[dict] (human-readable evidence indicators)
    """
    domain_comp = extract_domain_components(url)
    norm_host = domain_comp["normalized_hostname"]
    scheme = domain_comp["scheme"]

    cache_key = f"domain_intel:{scheme}:{norm_host}:{domain_comp['port'] or (443 if scheme == 'https' else 80)}"
    if use_cache:
        cached = DOMAIN_INTELLIGENCE_CACHE.get(cache_key)
        if cached:
            return cached

    # 1. DNS Resolution
    dns_res = resolve_dns(norm_host, timeout=2.0)

    # 2. TLS Inspection (for HTTPS URLs or port 443)
    if (scheme == "https" or domain_comp["port"] == 443) and dns_res["is_ssrf_safe"]:
        tls_res = analyze_tls_certificate(norm_host, port=domain_comp["port"] or 443, timeout=2.0,
                                          resolved_ips=dns_res["resolved_ips"])
    else:
        tls_res = {
            "status": "UNAVAILABLE",
            "certificate_present": False,
            "certificate_valid": False,
            "days_until_expiry": None,
            "issuer": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "error_message": "TLS inspection skipped: destination DNS is unsafe or unavailable." if scheme == "https" else "HTTP non-TLS protocol",
        }

    # 3. Domain Registration (WHOIS)
    reg_res = get_domain_registration(norm_host)

    # 4. Reputation Lookup
    aggregator = MultiProviderAggregator([LocalBlacklistProvider()])
    rep_res = aggregator.aggregate_lookup(norm_host)

    # 5. Extract Domain Feature Vector for ML
    domain_features = {
        "domain_age_days": reg_res["domain_age_days"] if reg_res["domain_age_days"] is not None else -1,
        "is_recent_registration": 1 if reg_res["is_recent_registration"] else 0,
        "dns_resolved": 1 if dns_res["status"] == "SUCCESS" else 0,
        "resolved_ip_count": dns_res["resolved_ip_count"],
        "has_private_ip": 1 if dns_res["has_private_ip"] else 0,
        "is_ssrf_safe": 1 if dns_res["is_ssrf_safe"] else 0,
        "tls_certificate_valid": 1 if tls_res["certificate_valid"] else 0,
        "tls_days_until_expiry": tls_res["days_until_expiry"] if tls_res["days_until_expiry"] is not None else -1,
        "is_blacklisted": 1 if rep_res["malicious_provider_count"] > 0 else 0,
    }

    # 6. Generate Explainable Indicators
    indicators: List[Dict[str, Any]] = []

    if reg_res.get("is_recent_registration"):
        indicators.append({
            "code": "RECENT_DOMAIN_REGISTRATION",
            "category": "Registration",
            "severity": "MEDIUM",
            "source": reg_res.get("source", "RegistrationProvider"),
            "value": reg_res["domain_age_days"],
            "description": f"Domain was registered recently ({reg_res['domain_age_days']} days ago)."
        })

    if dns_res.get("status") in ("DOMAIN_NOT_FOUND", "DNS_TIMEOUT", "DNS_PROVIDER_ERROR"):
        indicators.append({
            "code": "DNS_RESOLUTION_FAILED",
            "category": "DNS",
            "severity": "MEDIUM",
            "source": "DNS",
            "value": dns_res["status"],
            "description": f"DNS resolution failed with status '{dns_res['status']}'."
        })

    if dns_res.get("has_private_ip"):
        indicators.append({
            "code": "PRIVATE_IP_RESOLVED",
            "category": "Security",
            "severity": "HIGH",
            "source": "DNS/IP",
            "value": dns_res["resolved_ips"],
            "description": "Domain resolved to a private, loopback, or internal network IP address (SSRF risk)."
        })

    if scheme == "https":
        if tls_res.get("status") == "INVALID":
            indicators.append({
                "code": "TLS_CERTIFICATE_INVALID",
                "category": "TLS/SSL",
                "severity": "HIGH",
                "source": "TLS",
                "value": tls_res.get("error_message"),
                "description": "HTTPS connection SSL/TLS certificate verification failed."
            })
        elif tls_res.get("status") == "EXPIRED":
            indicators.append({
                "code": "TLS_CERTIFICATE_EXPIRED",
                "category": "TLS/SSL",
                "severity": "HIGH",
                "source": "TLS",
                "value": tls_res.get("days_until_expiry"),
                "description": "HTTPS SSL/TLS certificate has expired."
            })

    if rep_res.get("reputation_status") == "MALICIOUS":
        indicators.append({
            "code": "DOMAIN_REPUTATION_MALICIOUS",
            "category": "Reputation",
            "severity": "CRITICAL",
            "source": "ReputationProvider",
            "value": "MALICIOUS",
            "description": "Domain is listed as malicious by threat intelligence providers."
        })
    elif rep_res.get("reputation_status") == "SUSPICIOUS":
        indicators.append({
            "code": "DOMAIN_REPUTATION_SUSPICIOUS",
            "category": "Reputation",
            "severity": "HIGH",
            "source": "ReputationProvider",
            "value": "SUSPICIOUS",
            "description": "Domain is flagged as suspicious by threat intelligence providers."
        })

    payload = {
        "feature_version": "3.0",
        "domain_components": domain_comp,
        "dns": dns_res,
        "tls": tls_res,
        "registration": reg_res,
        "reputation": rep_res,
        "domain_features": domain_features,
        "indicators": indicators,
    }

    if use_cache and norm_host:
        DOMAIN_INTELLIGENCE_CACHE.set(cache_key, payload)

    return payload
