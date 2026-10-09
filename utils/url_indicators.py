# utils/url_indicators.py
"""
utils/url_indicators.py
-----------------------
Suspicious Pattern Indicator Engine for SecureSight URL analysis.
Evaluates advanced features and URL structure to generate explainable, rule-based indicators
and risk factor breakdowns.
"""

from typing import Dict, List, Any
from utils.url_features import extract_advanced_url_features


def analyze_url_indicators(url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Analyze URL features and identify specific suspicious security indicators.

    Returns:
        Dict containing:
            - indicators (List[Dict]): Identified risk indicators with code, category, severity, description.
            - total_risk_score (float): Calculated aggregate risk score (0.0 to 100.0).
            - risk_level (str): LOW, MEDIUM, HIGH, CRITICAL.
    """
    if features is None:
        features = extract_advanced_url_features(url)

    indicators: List[Dict[str, Any]] = []

    # 1. IP Hostname
    if features.get("has_ip") == 1:
        indicators.append({
            "code": "IP_AS_HOSTNAME",
            "category": "Domain",
            "severity": "HIGH",
            "weight": 25,
            "description": "URL uses a raw IP address instead of a domain name."
        })

    # 2. URL Shortener
    if features.get("is_shortener") == 1:
        indicators.append({
            "code": "URL_SHORTENER_DETECTED",
            "category": "Domain",
            "severity": "MEDIUM",
            "weight": 15,
            "description": "URL uses a known shortening service which masks the final destination."
        })

    # 3. High Risk TLD
    if features.get("is_suspicious_tld") == 1:
        indicators.append({
            "code": "HIGH_RISK_TLD",
            "category": "Domain",
            "severity": "MEDIUM",
            "weight": 15,
            "description": "Top-level domain (TLD) is frequently associated with malicious or spam activity."
        })

    # 4. Brand spoofing / Typosquatting
    if features.get("brand_in_subdomain") == 1:
        indicators.append({
            "code": "BRAND_IN_SUBDOMAIN",
            "category": "Spoofing",
            "severity": "HIGH",
            "weight": 20,
            "description": "Target brand name detected inside subdomain, commonly used in phishing schemes."
        })
    elif features.get("brand_in_path") == 1:
        indicators.append({
            "code": "BRAND_IN_PATH",
            "category": "Spoofing",
            "severity": "MEDIUM",
            "weight": 10,
            "description": "Target brand name detected in URL path."
        })

    if features.get("is_typosquatting") == 1:
        indicators.append({
            "code": "TYPOSQUATTING_SUSPECTED",
            "category": "Spoofing",
            "severity": "HIGH",
            "weight": 20,
            "description": "Domain name closely mimics a known target brand (low Levenshtein distance)."
        })


    # 5. Excessive Subdomains
    if features.get("subdomain_depth", 0) >= 3:
        indicators.append({
            "code": "EXCESSIVE_SUBDOMAINS",
            "category": "Structure",
            "severity": "MEDIUM",
            "weight": 15,
            "description": "High number of subdomains detected, often used to bypass filters."
        })

    # 6. High Shannon Entropy
    if features.get("url_entropy", 0.0) >= 4.5:
        indicators.append({
            "code": "HIGH_ENTROPY",
            "category": "Statistical",
            "severity": "MEDIUM",
            "weight": 10,
            "description": "URL exhibits high character entropy, indicating randomness or obfuscation."
        })

    # 7. Suspicious Keywords
    kw_count = features.get("suspicious_keyword_count", 0)
    if kw_count > 0:
        indicators.append({
            "code": "SUSPICIOUS_KEYWORDS",
            "category": "Lexical",
            "severity": "HIGH" if kw_count >= 3 else "MEDIUM",
            "weight": min(30, kw_count * 10),
            "description": f"Detected {kw_count} suspicious keyword(s) related to login, security, or authentication."
        })

    # 8. @ Symbol Obfuscation
    if "@" in __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(url).netloc:
        indicators.append({
            "code": "AT_SYMBOL_OBFUSCATION",
            "category": "Obfuscation",
            "severity": "HIGH",
            "weight": 25,
            "description": "URL contains '@' symbol, which ignores preceding authority and redirects users."
        })

    # 9. Hex / Base64 Encoding
    if features.get("hex_encoding_count", 0) >= 3:
        indicators.append({
            "code": "EXCESSIVE_HEX_ENCODING",
            "category": "Obfuscation",
            "severity": "MEDIUM",
            "weight": 15,
            "description": "Multiple hex-encoded (%XX) characters detected in URL."
        })

    # 10. Non-standard Port
    if features.get("is_non_standard_port") == 1:
        indicators.append({
            "code": "NON_STANDARD_PORT",
            "category": "Protocol",
            "severity": "MEDIUM",
            "weight": 15,
            "description": "URL specifies a non-standard web network port."
        })

    # 11. Double Slash in Path
    if features.get("double_slash_in_path") == 1:
        indicators.append({
            "code": "DOUBLE_SLASH_IN_PATH",
            "category": "Obfuscation",
            "severity": "MEDIUM",
            "weight": 10,
            "description": "Double slash '//' present inside URL path component."
        })

    evidence_keys = {
        "IP_AS_HOSTNAME": "has_ip", "HIGH_RISK_TLD": "is_suspicious_tld",
        "URL_SHORTENER": "is_shortener", "SUSPICIOUS_KEYWORDS": "suspicious_keyword_count",
        "HIGH_ENTROPY": "url_entropy", "EXCESSIVE_HEX_ENCODING": "hex_encoding_count",
        "NON_STANDARD_PORT": "is_non_standard_port", "DOUBLE_SLASH_IN_PATH": "double_slash_in_path",
        "TYPOSQUATTING": "min_brand_distance", "AT_SYMBOL_OBFUSCATION": "at_count"}
    for indicator in indicators:
        feature = evidence_keys.get(indicator['code'], 'url_len')
        indicator.update(feature=feature, value=features.get(feature), reason=indicator['description'])
    # Aggregate heuristic evidence, never a calibrated probability.
    raw_risk = sum(ind["weight"] for ind in indicators)
    total_risk_score = min(100.0, float(raw_risk))

    if total_risk_score >= 60.0:
        risk_level = "CRITICAL"
    elif total_risk_score >= 35.0:
        risk_level = "HIGH"
    elif total_risk_score >= 15.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "indicators": indicators,
        "indicator_count": len(indicators),
        "total_risk_score": total_risk_score,
        "risk_level": risk_level,
    }
