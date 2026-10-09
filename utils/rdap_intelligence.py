"""IANA-discovered RDAP, normalized without retaining registrant vCards."""
from datetime import datetime, timezone
import re
import logging
import time
from urllib.parse import quote, urlsplit
from app.security.json_fetch import fetch_json
from app.security.urls import validate_url
from utils.domain_cache import TTLMemoryCache

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
CACHE = TTLMemoryCache(default_ttl=3600, max_entries=256)
logger = logging.getLogger(__name__)


def timestamp(value, now=None, allow_future=False):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        parsed = parsed.astimezone(timezone.utc)
        if parsed.year < 1980 or (not allow_future and parsed > (now or datetime.now(timezone.utc))):
            return None
        return parsed
    except (ValueError, OverflowError):
        return None


def normalize_rdap(data, domain, now=None):
    now = now or datetime.now(timezone.utc)
    if data.get("objectClassName") != "domain" or str(data.get("ldhName", "")).lower().rstrip(".") != domain:
        raise ValueError("RDAP domain identity mismatch")
    events = data.get("events", [])
    if not isinstance(events, list) or len(events) > 64:
        raise ValueError("Invalid RDAP events")
    dates = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        action = event.get("eventAction")
        if action in {"registration", "last changed", "expiration"}:
            value = timestamp(event.get("eventDate"), now, allow_future=action == "expiration")
            if value:
                dates.setdefault(action, []).append(value)
    created = min(dates.get("registration", []), default=None)
    updated = max(dates.get("last changed", []), default=None)
    expiry = max(dates.get("expiration", []), default=None)
    if expiry and created and expiry < created:
        expiry = None
    entities = data.get("entities", [])
    registrar = None
    if isinstance(entities, list):
        for entity in entities[:32]:
            if isinstance(entity, dict) and isinstance(entity.get("roles"), list) and "registrar" in entity["roles"][:16]:
                handle = entity.get("handle")
                if isinstance(handle, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", handle):
                    registrar = handle
                    break
    nameservers = data.get("nameservers", [])
    ns = [v["ldhName"].lower() for v in nameservers[:32] if isinstance(v, dict) and
          isinstance(v.get("ldhName"), str) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", v["ldhName"])] if isinstance(nameservers, list) else []
    statuses = data.get("status", [])
    statuses = [v for v in statuses[:32] if isinstance(v, str) and re.fullmatch(r"[a-zA-Z -]{1,64}", v)] if isinstance(statuses, list) else []
    age = (now - created).days if created else None
    dnssec = data.get("secureDNS", {})
    return dict(status="AVAILABLE" if created else "PARTIAL", creation_date=created.isoformat() if created else None,
        updated_date=updated.isoformat() if updated else None, expiration_date=expiry.isoformat() if expiry else None,
        domain_age_days=age, domain_age_months=round(age / 30.4375, 2) if age is not None else None,
        domain_age_years=round(age / 365.25, 2) if age is not None else None,
        is_recent_registration=age is not None and age <= 30, registrar=registrar,
        registration_statuses=statuses, nameservers=ns, dnssec=dnssec.get("delegationSigned") if isinstance(dnssec, dict) and type(dnssec.get("delegationSigned")) is bool else None,
        owner_status="UNKNOWN_OR_REDACTED", source="RDAP", retrieved_at=now.isoformat(), observed_at=now.isoformat(),
        creation_date_source="registration_event" if created else None)


def lookup_rdap(domain):
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", domain):
        raise ValueError("Invalid RDAP domain")
    cached = CACHE.get("rdap:" + domain)
    if cached:
        return cached
    deadline = time.monotonic() + 4
    bootstrap = CACHE.get("bootstrap")
    if bootstrap is None:
        bootstrap = fetch_json(BOOTSTRAP_URL, deadline)
        services = bootstrap.get("services")
        if not isinstance(services, list) or len(services) > 3000:
            raise ValueError("Invalid RDAP discovery")
        CACHE.set("bootstrap", bootstrap)
    tld = domain.rsplit(".", 1)[-1]
    bases = []
    for service in bootstrap["services"]:
        if isinstance(service, list) and len(service) == 2 and isinstance(service[0], list) and isinstance(service[1], list) and tld in service[0]:
            bases = service[1][:2]
            break
    for base in bases:
        try:
            base = validate_url(base)
            parts = urlsplit(base)
            if parts.scheme != "https" or parts.query or parts.fragment:
                continue
            result = normalize_rdap(fetch_json(base.rstrip("/") + "/domain/" + quote(domain, safe=""), deadline), domain)
            result["provider"] = parts.hostname
            result["discovery_source"] = BOOTSTRAP_URL
            CACHE.set("rdap:" + domain, result)
            return result
        except Exception:
            logger.info("rdap_provider_unavailable")
            continue
    raise ValueError("RDAP unavailable for domain")
