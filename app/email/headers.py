"""Header observations are untrusted; mailbox names are not authenticated identities."""
import hashlib
import ipaddress
import re
import unicodedata
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from app.security.urls import validate_url, InvalidURL
from utils.domain_extraction import extract_domain_components
from app.brand.similarity import skeleton


def domain(value):
    try:
        return extract_domain_components(validate_url("https://" + value))["normalized_hostname"]
    except (InvalidURL, ValueError, TypeError):
        return None


def registrable(value):
    return extract_domain_components("https://" + value)["normalized_registrable_domain"] if value else None


def relationship(left, right):
    if not left or not right:
        return "UNKNOWN"
    return "ALIGNED" if left == right else "PARTIALLY_ALIGNED" if registrable(left) == registrable(right) else "MISALIGNED"


def timestamp(value):
    try:
        date = parsedate_to_datetime(value)
        return date.astimezone(timezone.utc) if date.tzinfo else None
    except (TypeError, ValueError, OverflowError):
        return None


def analyze_headers(message):
    names = [name.lower() for name, _ in message.raw_items()]
    duplicates = sorted(set(name for name in names if names.count(name) > 1 and name in {"from", "sender", "reply-to", "return-path", "date", "subject", "message-id", "content-type", "mime-version"}))
    identities = {}
    unicode_flags = []
    for field in ("From", "Sender", "Reply-To", "Return-Path", "To", "Cc"):
        values = [str(value) for value in message.get_all(field, [])]
        try:
            boxes = getaddresses(values)[:32]
        except (ValueError, IndexError):
            boxes = []
        parsed = []
        for display, address in boxes:
            host = address.rsplit("@", 1)[-1] if "@" in address else None
            normalized = domain(host) if host else None
            parsed.append({"display_name": display[:128], "mailbox_sha256": hashlib.sha256(address.encode()).hexdigest(),
                "domain": normalized, "registrable_domain": registrable(normalized), "valid_mailbox": bool(normalized and "@" in address)})
        identities[field.lower()] = parsed
        value = " ".join(values)
        scripts = {unicodedata.name(c, "").split(" ")[0] for c in value if c.isalpha() and ord(c) > 127}
        if "xn--" in value.casefold():
            unicode_flags.append("PUNYCODE")
        if any(unicodedata.category(c) in {"Cf", "Cc"} and c not in "\r\n\t" for c in value):
            unicode_flags.append("INVISIBLE_CONTROL")
        if len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1 or (any(c.isascii() and c.isalpha() for c in value) and scripts & {"CYRILLIC", "GREEK"}):
            unicode_flags.append("MIXED_SCRIPTS")
        if unicodedata.normalize("NFKC", value) != value:
            unicode_flags.append("NORMALIZATION_DIFFERENCE")
        if skeleton(value.casefold()) != value.casefold():
            unicode_flags.append("CONFUSABLE_CHARACTERS")
    def first(field):
        boxes = identities[field]
        return boxes[0]["domain"] if len(boxes) == 1 and field not in duplicates else None
    from_domain = first("from")
    comparisons = {field: relationship(from_domain, first(field)) for field in ("sender", "reply-to", "return-path")}
    received = []
    dates = []
    for value in message.get_all("Received", [])[:32]:
        value = str(value)
        date = timestamp(value.rsplit(";", 1)[-1]) if ";" in value else None
        if date:
            dates.append(date)
        ips = []
        for token in re.findall(r"\[([^\]]+)\]", value):
            try:
                ip = ipaddress.ip_address(token.removeprefix("IPv6:"))
                ips.append({"ip": str(ip) if ip.is_global else "PRIVATE_REDACTED", "scope": "PUBLIC" if ip.is_global else "PRIVATE_OR_SPECIAL"})
            except ValueError:
                continue
        hosts = re.findall(r"\b(?:from|by)\s+([a-zA-Z0-9.-]+)", value)[:2]
        received.append({"header_sha256": hashlib.sha256(value.encode()).hexdigest(), "hosts": hosts,
            "ips": ips, "timestamp": date.isoformat() if date else None, "trust": "UNTRUSTED_UPLOAD", "reverse_dns": "UNAVAILABLE"})
    chronology = any(newer < older for newer, older in zip(dates, dates[1:]))
    date = timestamp(str(message.get("Date", "")))
    now = datetime.now(timezone.utc)
    return {"version": "11.0", "identities": identities, "from_domain": from_domain,
        "relationships": comparisons, "duplicate_headers": duplicates, "unicode_indicators": sorted(set(unicode_flags)),
        "subject": str(message.get("Subject", ""))[:512], "message_id_sha256": hashlib.sha256(str(message.get("Message-ID", "")).encode()).hexdigest(),
        "header_inventory": [{"name": name[:64], "sha256": hashlib.sha256(str(value).encode()).hexdigest()} for name, value in message.raw_items()][:128],
        "received": {"hops": received, "hop_count": len(message.get_all("Received", [])), "chronology_anomaly": chronology, "trust_boundary_verified": False},
        "timestamps": {"date": date.isoformat() if date else None, "ingested_at": now.isoformat(),
            "future_date": bool(date and (date - now).total_seconds() > 86400), "date_after_received": bool(date and dates and (date - dates[0]).total_seconds() > 3600)},
        "unsubscribe_present": bool(message.get_all("List-Unsubscribe")), "unknown_headers_trusted": False}
