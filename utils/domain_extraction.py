# utils/domain_extraction.py
"""
utils/domain_extraction.py
---------------------------
Domain Extraction & Normalization Engine for SecureSight Phase 3.
Provides public-suffix aware domain parsing, IDN/Punycode handling, and hostname normalization.
"""

from urllib.parse import urlparse
import tldextract

DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def normalize_domain(domain: str) -> str:
    """
    Normalize domain name.
    - Strips whitespace & trailing dots
    - Converts to lowercase
    - Encodes IDN/Unicode to Punycode ASCII if necessary
    """
    if not domain:
        return ""
    
    domain = domain.strip().rstrip(".").lower()
    
    # Handle IDN / Punycode conversion safely
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Invalid domain encoding") from error
        
    return domain


def extract_domain_components(url: str) -> dict:
    """
    Extract public-suffix aware domain components from raw URL string.
    Returns dictionary with original and normalized hostname, registrable domain,
    subdomain, TLD, scheme, and port.
    
    Raises:
        ValueError: If URL is empty or invalid.
    """
    if not url or not url.strip():
        raise ValueError("URL cannot be empty")

    url = url.strip()
    working_url = url if "://" in url else "http://" + url
    parsed = urlparse(working_url)

    original_hostname = parsed.hostname or ""
    normalized_hostname = normalize_domain(original_hostname)
    port = parsed.port
    scheme = parsed.scheme.lower() if parsed.scheme else "http"

    ext = DOMAIN_EXTRACTOR(working_url)
    subdomain = ext.subdomain or ""
    domain_name = ext.domain or ""
    suffix = ext.suffix or ""

    registrable_domain = f"{domain_name}.{suffix}" if (domain_name and suffix) else normalized_hostname
    normalized_registrable = normalize_domain(registrable_domain)

    is_idn = int(any(ord(c) > 127 for c in original_hostname) or "xn--" in normalized_hostname)

    return {
        "original_hostname": original_hostname,
        "normalized_hostname": normalized_hostname,
        "registrable_domain": registrable_domain,
        "normalized_registrable_domain": normalized_registrable,
        "subdomain": subdomain,
        "domain_name": domain_name,
        "tld": suffix,
        "scheme": scheme,
        "port": port,
        "is_idn": is_idn,
    }
