"""Observed feature contract shared by training and the scan service."""
import numpy as np
import pandas as pd
from utils.url_features import extract_advanced_url_features
from utils.html_features import HTML_FEATURE_NAMES
from utils.web_intelligence import CONTENT_FEATURE_NAMES, analyze_web_intelligence
from utils.domain_intelligence import analyze_domain_intelligence

FEATURE_SCHEMA_VERSION = "5.1.1"
URL_FEATURE_ORDER = list(extract_advanced_url_features("https://example.com/"))
DOMAIN_FEATURE_ORDER = ["domain_age_days", "is_recent_registration", "dns_resolved", "resolved_ip_count",
    "has_private_ip", "is_ssrf_safe", "tls_certificate_valid", "tls_days_until_expiry", "is_blacklisted"]
FEATURE_ORDER = URL_FEATURE_ORDER + DOMAIN_FEATURE_ORDER + HTML_FEATURE_NAMES + CONTENT_FEATURE_NAMES


def aggregate_feature_dict(url_features, domain_intelligence, web_intelligence):
    raw = dict(url_features)
    raw.update(domain_intelligence.get("domain_features", {}))
    if domain_intelligence.get("registration", {}).get("domain_age_days") is None:
        raw["domain_age_days"] = raw["is_recent_registration"] = None
    if domain_intelligence.get("tls", {}).get("status") not in {"VALID", "EXPIRING_SOON", "INVALID"}:
        raw["tls_certificate_valid"] = raw["tls_days_until_expiry"] = None
    if domain_intelligence.get("reputation", {}).get("reputation_status") in {"UNKNOWN", "ERROR", "UNAVAILABLE", "SUSPICIOUS", None}:
        raw["is_blacklisted"] = None
    raw.update(web_intelligence.get("combined_web_features", {}))
    return {name: float(raw[name]) if raw.get(name) is not None and raw[name] >= 0 else None for name in FEATURE_ORDER}


def extract_unified_feature_dict(url, html_content_override=None):
    return aggregate_feature_dict(extract_advanced_url_features(url), analyze_domain_intelligence(url),
                                  analyze_web_intelligence(url, html_content_override))


def align_features_df(df):
    return df.reindex(columns=FEATURE_ORDER).apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
