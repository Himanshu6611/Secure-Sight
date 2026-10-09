"""Deterministic observed language, never a standalone phishing classifier."""
import re
from bs4 import BeautifulSoup
from app.security.urls import validate_url, InvalidURL
from .headers import relationship
from urllib.parse import urlsplit

PATTERNS = {
    "urgency": r"\b(?:urgent|immediately|within \d+ hours|act now|today only)\b",
    "credentials": r"\b(?:password|credential|login|sign in|verify your account)\b",
    "mfa_otp": r"\b(?:otp|mfa|one.time password|verification code)\b",
    "financial": r"\b(?:wire transfer|bank account|payment|invoice|gift cards?)\b",
    "bank_change": r"\b(?:new bank account|bank account (?:has )?changed|updated bank details|change.{0,24}bank|new payment details)\b",
    "account_suspension": r"\b(?:account.{0,20}suspend|account.{0,20}locked|access.{0,20}blocked)\b",
    "delivery_document": r"\b(?:delivery|parcel|shared document|document waiting)\b",
    "identity_verification": r"\b(?:verify.{0,20}identity|identity verification|confirm.{0,20}identity)\b",
    "security_alert": r"\b(?:security alert|unusual login|suspicious activity)\b",
    "executive": r"\b(?:ceo|chief executive|director|president|cfo)\b",
    "secrecy": r"\b(?:confidential|do not tell|keep.{0,16}secret|between us)\b",
    "fear": r"\b(?:legal action|arrest|penalty|lose access)\b"}


def analyze(bodies, headers):
    texts, urls, html = [], [], {"forms": 0, "hidden_elements": 0, "scripts": 0, "remote_images": 0, "external_resources": 0, "url_mismatches": []}
    def add(value, source, displayed=None):
        if not value or len(value) > 2048:
            return
        if value.lower().startswith(("http://", "https://")):
            urls.append({"value": value, "source": source})
            if displayed and displayed.lower().startswith(("http://", "https://")):
                try:
                    mismatch = relationship(urlsplit(validate_url(value)).hostname, urlsplit(validate_url(displayed)).hostname)
                    if mismatch == "MISALIGNED":
                        html["url_mismatches"].append({"destination_hostname": urlsplit(value).hostname, "displayed_hostname": urlsplit(displayed).hostname})
                except (InvalidURL, ValueError):
                    html["url_mismatches"].append({"status": "INVALID_DISPLAYED_OR_DESTINATION_URL"})
    for body in bodies:
        value = body["text"]
        if body["type"] == "text/html":
            soup = BeautifulSoup(value, "html.parser")
            html["forms"] += len(soup.find_all("form"))
            html["scripts"] += len(soup.find_all("script"))
            html["remote_images"] += sum(str(tag.get("src", "")).startswith(("http:", "https:")) for tag in soup.find_all("img"))
            html["external_resources"] += sum(bool(tag.get("src") or tag.get("href")) for tag in soup.find_all(("script", "link", "iframe")))
            html["hidden_elements"] += sum("display:none" in str(tag.get("style", "")).replace(" ", "").lower() or tag.has_attr("hidden") for tag in soup.find_all(True))
            for tag in soup.find_all("a")[:128]:
                add(str(tag.get("href", "")), "HTML_ANCHOR", tag.get_text(" ", strip=True))
            for tag in soup.find_all(("script", "style")):
                tag.decompose()
            value = soup.get_text(" ", strip=True)
        texts.append(value)
        for target in re.findall(r"https?://[^\s<>\"']+", value, flags=re.I)[:128]:
            add(target.rstrip(".,);"), "PLAIN_TEXT" if body["type"] == "text/plain" else "HTML_TEXT")
    text = " ".join([headers["subject"], *texts])[:65536]
    features = {name: bool(re.search(pattern, text, re.I)) for name, pattern in PATTERNS.items()}
    identity_mismatch = headers["relationships"]["reply-to"] == "MISALIGNED"
    bec = features["financial"] and (features["bank_change"] or (features["executive"] and features["secrecy"])) and (features["urgency"] or identity_mismatch)
    return {"version": "11.0", "status": "ANALYZED", "features": features, "html": html,
            "bec": {"candidate": bec, "context_available": False, "not_proof": True},
            "model_status": "MODEL_UNAVAILABLE", "model_probability": None, "snippet": text[:256],
            "_text": text, "_urls": urls[:128]}
