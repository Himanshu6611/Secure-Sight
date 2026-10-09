# feature_extraction.py
#!/usr/bin/env python3
"""
utils/feature_extraction.py
---------------------------
Functions that turn a raw URL string into a fixed‑size numeric feature vector.
"""

import re
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_TOKENS = [
    "login", "secure", "account", "update", "verify",
    "bank", "paypal", "webscr", "confirm", "billing",
    "reset", "signin", "admin", "password", "gift"
]

DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def _has_ip(hostname: str) -> bool:
    """Return 1 if hostname looks like an IPv4 address."""
    return bool(IP_PATTERN.fullmatch(hostname))

def _entropy(s: str) -> float:
    """Shannon entropy – useful for detecting obfuscation."""
    from collections import Counter
    import math
    if not s:
        return 0.0
    probs = [c / len(s) for c in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url: str) -> dict:
    """
    Returns a dictionary of numeric features for a single URL.
    All keys are column‑friendly (no spaces).
    """
    # ------------------------------------------------------------------
    # Normalise / parse
    if not url:
        raise ValueError("Empty URL")
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # ------------------------------------------------------------------
    # Structural statistics
    url_len = len(url)
    dot_cnt = hostname.count(".")
    hyphen_cnt = hostname.count("-")
    special_cnt = len(re.findall(r"[^\w]", url))
    digit_cnt = len(re.findall(r"\d", url))

    # ------------------------------------------------------------------
    # Token / semantic cues
    token_hits = sum(tok in url.lower() for tok in SUSPICIOUS_TOKENS)

    # ------------------------------------------------------------------
    # Domain details via tldextract
    ext = DOMAIN_EXTRACTOR(url)
    domain_len = len(ext.domain)
    subdomain_depth = len(ext.subdomain.split('.')) if ext.subdomain else 0

    # ------------------------------------------------------------------
    # Security‑related flags
    has_ip = int(_has_ip(hostname))
    https = int(parsed.scheme.lower() == "https")
    entropy = _entropy(url)

    # ------------------------------------------------------------------
    return {
        "url_len": url_len,
        "dot_cnt": dot_cnt,
        "hyphen_cnt": hyphen_cnt,
        "special_cnt": special_cnt,
        "digit_cnt": digit_cnt,
        "token_hits": token_hits,
        "domain_len": domain_len,
        "subdomain_depth": subdomain_depth,
        "has_ip": has_ip,
        "https": https,
        "entropy": entropy,
    }
