# utils/content_nlp.py
"""
utils/content_nlp.py
--------------------
Text Extraction & Content NLP Analysis Engine for SecureSight Phase 4.
Extracts visible textual content from HTML, computes normalized NLP scores (0.0 - 1.0) for
urgency, credential harvesting, financial language, login intent, and detects brand-domain mismatches.
"""

import os
import json
import logging
import re
from typing import Dict, Any
from bs4 import BeautifulSoup

from utils.url_config import TARGET_BRANDS
from utils.domain_extraction import extract_domain_components

KEYWORDS_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "phishing_keywords.json")
)


def _load_keywords() -> Dict[str, list]:
    if os.path.exists(KEYWORDS_FILE):
        try:
            with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            logging.getLogger(__name__).warning("keyword_configuration_unavailable")
    return {
        "authentication": ["login", "signin", "password", "verify account"],
        "urgency": ["immediately", "urgent", "account suspended", "warning"],
        "financial": ["payment", "billing", "credit card", "bank"],
        "credential": ["enter password", "confirm password", "otp", "pin"],
        "security": ["security alert", "unauthorized access", "verification"],
    }


PHISHING_KEYWORDS = _load_keywords()


def extract_visible_text(html_content: str) -> str:
    """Extract clean, visible body text from raw HTML."""
    if not html_content or not isinstance(html_content, str):
        return ""
    soup = BeautifulSoup(html_content, "html.parser")
    for script_or_style in soup(["script", "style", "noscript", "template"]):
        script_or_style.decompose()
    for hidden in list(soup.find_all(attrs={"hidden": True})):
        hidden.decompose()
    for hidden in list(soup.find_all(style=True)):
        if hidden.attrs and any(s in str(hidden.get("style", "")).replace(" ", "").lower() for s in ["display:none", "visibility:hidden"]):
            hidden.decompose()
    text = soup.get_text(separator=" ")
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    return " ".join(chunk for chunk in chunks if chunk)


def analyze_content_nlp(html_content: str, page_title: str, page_url: str) -> Dict[str, Any]:
    """
    Perform content NLP scoring and brand-domain mismatch detection.

    Returns:
        Dict containing:
            - content_features: Dict[str, float/int] (NLP scores for ML ensemble)
            - brand_mismatch_detected: bool
            - detected_brand: str or None
            - visible_text_snippet: str
    """
    visible_text = extract_visible_text(html_content)
    combined_text = f"{page_title} {visible_text}".lower()

    # Calculate category keyword matches
    auth_hits = sum(1 for kw in PHISHING_KEYWORDS.get("authentication", []) if re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", combined_text))
    urgency_hits = sum(1 for kw in PHISHING_KEYWORDS.get("urgency", []) if re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", combined_text))
    financial_hits = sum(1 for kw in PHISHING_KEYWORDS.get("financial", []) if re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", combined_text))
    credential_hits = sum(1 for kw in PHISHING_KEYWORDS.get("credential", []) if re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", combined_text))
    security_hits = sum(1 for kw in PHISHING_KEYWORDS.get("security", []) if re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", combined_text))

    total_phishing_kw_count = auth_hits + urgency_hits + financial_hits + credential_hits + security_hits

    # Normalize scores to 0.0 - 1.0 range
    login_language_score = min(1.0, auth_hits / 3.0)
    urgency_score = min(1.0, urgency_hits / 2.0)
    financial_language_score = min(1.0, financial_hits / 2.0)
    credential_score = min(1.0, credential_hits / 2.0)
    security_language_score = min(1.0, security_hits / 2.0)

    # Brand Title vs Domain Mismatch Detection
    page_info = extract_domain_components(page_url)
    page_reg_domain = page_info["normalized_registrable_domain"].lower()

    brand_mismatch = False
    detected_brand = None

    title_lower = page_title.lower()
    for brand in TARGET_BRANDS:
        if re.search(r"(?<!\w)" + re.escape(brand) + r"(?!\w)", title_lower):
            detected_brand = brand
            # Official domain check: exact brand domain or brand domain prefix
            # e.g. legitimate: microsoft.com, microsoft.net, microsoftonline.com
            # mismatch: fake-microsoft.com, evil-phish.com, micros0ft-verify.com
            exact_official = (page_reg_domain == f"{brand}.com" or page_reg_domain == f"{brand}.org" or page_reg_domain == f"{brand}.net")
            if brand == "microsoft":
                exact_official = exact_official or page_reg_domain in {"microsoftonline.com", "live.com", "office.com"}
            if not exact_official:
                brand_mismatch = True
            break

    return {
        "content_features": {
            "login_language_score": round(login_language_score, 4),
            "urgency_score": round(urgency_score, 4),
            "credential_score": round(credential_score, 4),
            "financial_language_score": round(financial_language_score, 4),
            "security_language_score": round(security_language_score, 4),
            "phishing_keyword_count": total_phishing_kw_count,
            "brand_domain_mismatch": 1 if brand_mismatch else 0,
        },
        "brand_mismatch_detected": brand_mismatch,
        "detected_brand": detected_brand,
        "visible_text_snippet": visible_text[:150] + "..." if len(visible_text) > 150 else visible_text,
    }
