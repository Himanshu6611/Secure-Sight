# utils/url_features.py
"""
utils/url_features.py
---------------------
Advanced URL Feature Extraction Engine for SecureSight.
Extracts deterministic lexical, structural, statistical, and pattern features.
Returns a normalized, ML-ready feature vector dictionary.
"""

import re
import math
import ipaddress
from collections import Counter
from functools import lru_cache
from urllib.parse import urlparse, parse_qs
import tldextract

from utils.url_config import (
    TARGET_BRANDS,
    URL_SHORTENERS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
)

# Pre-compiled Regex Patterns
IP_V4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IP_HEX_OCT_PATTERN = re.compile(r"^(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)){3}$")
HEX_ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def shannon_entropy(s: str) -> float:
    """Calculate Shannon Entropy of a string."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


@lru_cache(maxsize=65536)
def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_ip_address(hostname: str) -> bool:
    """Check if host is an IPv4 or Hex/Octal IP address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return bool(IP_HEX_OCT_PATTERN.fullmatch(hostname))


def extract_advanced_url_features(url: str) -> dict:
    """
    Extract comprehensive numerical and boolean feature vector from raw URL string.
    
    Raises:
        ValueError: If input URL is empty or whitespace.
    """
    if not url or not url.strip():
        raise ValueError("URL string cannot be empty")

    url = url.strip()
    raw_url = url

    # Ensure scheme for urllib parsing
    working_url = url if "://" in url else "http://" + url
    parsed = urlparse(working_url)

    # A conventional www prefix is not evidence of safety. Normalize only the
    # lexical view; DNS, TLS and fetching still use the original destination.
    if (parsed.hostname or "").lower().startswith("www."):
        authority = parsed.netloc
        prefix = authority.rfind("@") + 1
        authority = authority[:prefix] + authority[prefix + 4:]
        parsed = parsed._replace(netloc=authority)
        working_url = parsed.geturl()
        url = working_url if "://" in url else working_url.split("://", 1)[1]
        raw_url = url

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc or ""
    hostname = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    ext = DOMAIN_EXTRACTOR(working_url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if (ext.domain and ext.suffix) else (ext.domain or "")
    subdomain = ext.subdomain or ""
    domain = ext.domain or ""
    suffix = ext.suffix or ""


    # Check if host is behind an @ symbol (authority trick)
    userinfo = parsed.username or ""
    if "@" in netloc:
        userinfo = netloc.split("@")[0]

    # Include TLD check from both hostname suffix and userinfo/path if present
    full_tld_check = (suffix + " " + userinfo + " " + path).lower()


    # 1. Lexical Features
    url_len = len(url)
    hostname_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    dot_count = url.count(".")
    hyphen_count = url.count("-")
    underscore_count = url.count("_")
    slash_count = url.count("/")
    question_count = url.count("?")
    equal_count = url.count("=")
    at_count = url.count("@")
    ampersand_count = url.count("&")
    percent_count = url.count("%")
    tilde_count = url.count("~")

    digit_count = sum(c.isdigit() for c in url)
    letter_count = sum(c.isalpha() for c in url)
    uppercase_count = sum(c.isupper() for c in url)
    special_char_count = url_len - digit_count - letter_count

    digit_ratio = digit_count / url_len if url_len > 0 else 0.0
    letter_ratio = letter_count / url_len if url_len > 0 else 0.0
    uppercase_ratio = uppercase_count / url_len if url_len > 0 else 0.0
    special_ratio = special_char_count / url_len if url_len > 0 else 0.0

    # 2. Structural Features
    subdomain_depth = len(subdomain.split(".")) if subdomain else 0
    subdomain_len = len(subdomain)
    path_depth = len([p for p in path.split("/") if p])
    query_params_count = len(parse_qs(query)) if query else 0
    has_fragment = 1 if fragment else 0
    double_slash_in_path = 1 if "//" in path else 0

    # 3. Domain Features
    has_ip = 1 if is_ip_address(hostname) else 0
    tld_len = len(suffix)
    is_suspicious_tld = int(suffix.lower() in SUSPICIOUS_TLDS)
    is_shortener = 1 if (registered_domain.lower() in URL_SHORTENERS or hostname.lower() in URL_SHORTENERS) else 0

    # Brand targeting / typosquatting features
    hostname_lower = hostname.lower()
    subdomain_lower = subdomain.lower()
    path_lower = path.lower()

    brand_in_subdomain = 1 if any(b in subdomain_lower for b in TARGET_BRANDS) else 0
    brand_in_path = 1 if any(b in path_lower for b in TARGET_BRANDS) else 0

    # Min Levenshtein distance to known target brands (for typosquatting)
    # Distance 0 means exact brand domain (e.g. github.com), while distance 1-2 on non-exact domain indicates typosquatting.
    min_brand_distance = 999
    is_exact_brand = 0
    if domain:
        domain_lower = domain.lower()
        for brand in TARGET_BRANDS:
            dist = levenshtein_distance(domain_lower, brand)
            if dist == 0:
                is_exact_brand = 1
            if dist < min_brand_distance:
                min_brand_distance = dist
    if min_brand_distance == 999:
        min_brand_distance = -1

    is_typosquatting = 1 if (1 <= min_brand_distance <= 2 and not is_exact_brand) else 0


    # 4. Protocol Features
    has_scheme = 1 if "://" in raw_url else 0
    is_https = 1 if scheme == "https" else 0
    has_port = 1 if port is not None else 0
    is_non_standard_port = 1 if port and port not in (80, 443) else 0

    # 5. Statistical / Information Theory Features
    url_entropy = shannon_entropy(url)
    domain_entropy = shannon_entropy(hostname)
    path_entropy = shannon_entropy(path)

    # 6. Suspicious Pattern Features
    url_lower = url.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    suspicious_kw_domain_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in hostname_lower)
    suspicious_kw_path_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in path_lower)

    hex_encoding_count = len(HEX_ENCODING_PATTERN.findall(url))
    base64_strings_count = len(BASE64_PATTERN.findall(query))

    has_at_symbol = 1 if "@" in url else 0
    consecutive_hyphens = 1 if "--" in hostname else 0

    tokens = re.findall(r"[A-Za-z0-9]+", hostname + path + query)
    return {
        # Lexical
        "url_len": url_len,
        "hostname_len": hostname_len,
        "path_len": path_len,
        "query_len": query_len,
        "fragment_len": len(fragment),
        "colon_count": url.count(":"),
        "character_diversity": len(set(url)) / len(url),
        "token_count": len(tokens),
        "average_token_length": sum(map(len, tokens)) / len(tokens) if tokens else 0,
        "max_token_length": max(map(len, tokens), default=0),
        "encoded_ratio": len(HEX_ENCODING_PATTERN.findall(url)) * 3 / len(url),
        "punycode_detected": int("xn--" in hostname.lower()),
        "unicode_detected": int(any(ord(c) > 127 for c in url)),
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "question_count": question_count,
        "equal_count": equal_count,
        "at_count": at_count,
        "ampersand_count": ampersand_count,
        "percent_count": percent_count,
        "tilde_count": tilde_count,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "uppercase_count": uppercase_count,
        "special_char_count": special_char_count,
        "digit_ratio": round(digit_ratio, 4),
        "letter_ratio": round(letter_ratio, 4),
        "uppercase_ratio": round(uppercase_ratio, 4),
        "special_ratio": round(special_ratio, 4),

        # Structural
        "subdomain_depth": subdomain_depth,
        "subdomain_len": subdomain_len,
        "path_depth": path_depth,
        "query_params_count": query_params_count,
        "has_fragment": has_fragment,
        "double_slash_in_path": double_slash_in_path,

        # Domain
        "has_ip": has_ip,
        "tld_len": tld_len,
        "is_suspicious_tld": is_suspicious_tld,
        "is_shortener": is_shortener,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "min_brand_distance": min_brand_distance,
        "is_typosquatting": is_typosquatting,

        # Protocol
        "has_scheme": has_scheme,
        "is_https": is_https,
        "has_port": has_port,
        "is_non_standard_port": is_non_standard_port,

        # Statistical
        "url_entropy": round(url_entropy, 4),
        "domain_entropy": round(domain_entropy, 4),
        "path_entropy": round(path_entropy, 4),

        # Suspicious Patterns
        "suspicious_keyword_count": suspicious_keyword_count,
        "suspicious_kw_domain_count": suspicious_kw_domain_count,
        "suspicious_kw_path_count": suspicious_kw_path_count,
        "hex_encoding_count": hex_encoding_count,
        "base64_strings_count": base64_strings_count,
        "has_at_symbol": has_at_symbol,
        "consecutive_hyphens": consecutive_hyphens,
    }
