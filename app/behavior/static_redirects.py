"""Inspect the existing Phase 4 soup; never evaluate scripts or follow static targets."""
import re
from urllib.parse import urljoin
from app.security.urls import validate_url, InvalidURL
from .privacy import redact_url
from utils.domain_extraction import extract_domain_components

META = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*;\s*url\s*=\s*(.*?)\s*$", re.IGNORECASE)
JS = re.compile(r"(?:(?:window\.|document\.)?location(?:\.href)?\s*=\s*|(?:window\.|document\.)?location\.(?:replace|assign)\s*\(\s*)(['\"])([^'\"\r\n]{1,2048})\1", re.IGNORECASE)


def inspect_static_behavior(soup, base_url, config):
    results = []
    def record(kind, target, delay=None):
        if len(results) >= config["max_static_destinations"]:
            return
        candidate = urljoin(base_url, target.strip().strip("'\""))
        try:
            candidate = validate_url(candidate)
            domain = extract_domain_components(candidate)["normalized_registrable_domain"]
            state = "NOT_FOLLOWED"
        except (InvalidURL, ValueError):
            domain, state = None, "DESTINATION_BLOCKED"
        results.append({"redirect_type": kind, "destination_url": redact_url(candidate), "destination_domain": domain,
                        "delay_seconds": delay, "status": state, "executed": False,
                        "confidence": .95 if kind == "META_REFRESH" else .6, "source": "phase_4_static"})
    for tag in soup.find_all("meta"):
        if str(tag.get("http-equiv", "")).lower() == "refresh":
            match = META.match(str(tag.get("content", "")))
            if match:
                delay = float(match.group(1))
                if delay <= 86400:
                    record("META_REFRESH", match.group(2), delay)
    for script in soup.find_all("script"):
        if script.get("src") or str(script.get("type", "")).lower() in {"application/ld+json", "application/json"}:
            continue
        text = script.get_text()
        # This is a syntactic pattern indicator: comments/strings/dead code can match.
        for match in JS.finditer(text):
            record("JAVASCRIPT_PATTERN", match.group(2))
            if len(results) >= config["max_static_destinations"]:
                break
    return {"status": "ANALYZED", "destinations": results,
            "destination_limit_reached": len(results) >= config["max_static_destinations"],
            "window_open_pattern_count": sum(bool(re.search(r"\bwindow\.open\s*\(", s.get_text())) for s in soup.find_all("script")),
            "target_blank_count": sum(str(a.get("target", "")).lower() == "_blank" for a in soup.find_all("a")),
            "challenge_pattern_detected": any(soup.find(attrs={attr: re.compile(r"captcha|challenge", re.IGNORECASE)}) is not None for attr in ("id", "class")),
            "iframe_count": len(soup.find_all("iframe")), "dynamic_execution": "NOT_RUN"}
