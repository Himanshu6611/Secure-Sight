# utils/registration_intelligence.py
"""
utils/registration_intelligence.py
-----------------------------------
Domain Registration & Age Intelligence Engine for SecureSight Phase 3.
Retrieves and parses WHOIS data to determine domain creation date, domain age in days,
expiration, registrar, and registration availability status.
"""

import datetime
import logging
import re
from typing import Dict, Any, Optional

try:
    import whois
except ImportError:
    whois = None

from app.security.outbound import whois_text
from utils.domain_extraction import DOMAIN_EXTRACTOR

logger = logging.getLogger(__name__)


def _parse_date(date_val: Any) -> Optional[datetime.datetime]:
    """Safely parse WHOIS creation/expiration date values."""
    if not date_val:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime.datetime):
        return date_val
    if isinstance(date_val, str):
        try:
            import pandas as pd
            return pd.to_datetime(date_val).to_pydatetime()
        except Exception:
            return None
    return None


def _whois_registration(domain: str) -> Dict[str, Any]:
    """
    Retrieve domain WHOIS registration metadata and compute domain age.

    Returns:
        Dict containing:
            - status (str): AVAILABLE, PARTIAL, UNAVAILABLE, ERROR
            - creation_date (str or None)
            - expiration_date (str or None)
            - domain_age_days (int or None)
            - is_recent_registration (bool)
            - registrar (str or None)
    """
    if not domain or not isinstance(domain, str):
        return {
            "status": "UNAVAILABLE",
            "creation_date": None,
            "expiration_date": None,
            "domain_age_days": None,
            "is_recent_registration": False,
            "registrar": None,
        }

    domain = domain.strip().lower().rstrip(".")

    if whois is None:
        return {
            "status": "UNAVAILABLE",
            "creation_date": None,
            "expiration_date": None,
            "domain_age_days": None,
            "is_recent_registration": False,
            "registrar": None,
        }

    try:
        ext = DOMAIN_EXTRACTOR(domain)
        registered_domain = f"{ext.domain}.{ext.suffix}" if (ext.domain and ext.suffix) else (ext.domain or domain)
        if not registered_domain:
            return {
                "status": "UNAVAILABLE",
                "creation_date": None,
                "expiration_date": None,
                "domain_age_days": None,
                "is_recent_registration": False,
                "registrar": None,
            }

        w_text = whois_text(registered_domain)
        if not w_text:
            return {
                "status": "UNAVAILABLE",
                "creation_date": None,
                "expiration_date": None,
                "domain_age_days": None,
                "is_recent_registration": False,
                "registrar": None,
            }

        w = whois.parser.WhoisEntry.load(registered_domain, w_text)

        creation_dt = _parse_date(w.creation_date)
        expiration_dt = _parse_date(w.expiration_date)
        registrar = str(w.registrar) if getattr(w, "registrar", None) else None
        if registrar and (len(registrar) > 256 or any(c in registrar for c in "<>\x00")):
            registrar = None
        updated_dt = _parse_date(getattr(w, "updated_date", None))
        if updated_dt:
            candidate = updated_dt.replace(tzinfo=datetime.timezone.utc) if updated_dt.tzinfo is None else updated_dt
            if candidate > datetime.datetime.now(datetime.timezone.utc) or candidate.year < 1980:
                updated_dt = None
        nameservers = getattr(w, "name_servers", None) or []
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        nameservers = [v.lower() for v in nameservers[:32] if isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", v)] if isinstance(nameservers, list) else []

        domain_age_days = None
        is_recent = False

        if creation_dt:
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            if creation_dt.tzinfo is not None:
                diff_days = (now_dt - creation_dt).days
            else:
                diff_days = (now_dt.replace(tzinfo=None) - creation_dt).days

            if diff_days < 0 or creation_dt.year < 1980:
                creation_dt = None
            else:
                domain_age_days = diff_days
                is_recent = domain_age_days <= 30

        status = "AVAILABLE" if (creation_dt or registrar) else "PARTIAL"

        return {
            "status": status,
            "creation_date": creation_dt.isoformat() if creation_dt else None,
            "expiration_date": expiration_dt.isoformat() if expiration_dt else None,
            "domain_age_days": domain_age_days,
            "is_recent_registration": is_recent,
            "registrar": registrar,
            "updated_date":updated_dt.isoformat() if updated_dt else None,
            "nameservers":nameservers, "dnssec":None,
        }

    except Exception as e:
        logger.info("whois_lookup_failed")
        return {
            "status": "ERROR",
            "creation_date": None,
            "expiration_date": None,
            "domain_age_days": None,
            "is_recent_registration": False,
            "registrar": None,
        }


def get_domain_registration(domain: str) -> Dict[str, Any]:
    """RDAP first; bounded shared WHOIS gateway as compatibility fallback."""
    from utils.rdap_intelligence import lookup_rdap
    if not isinstance(domain, str) or not domain:
        return _whois_registration(domain)
    ext = DOMAIN_EXTRACTOR(domain.lower().rstrip("."))
    registered = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain
    partial = None
    try:
        partial = lookup_rdap(registered)
        if partial.get("domain_age_days") is not None:
            return partial
    except Exception:
        logger.info("rdap_lookup_unavailable")
    result = _whois_registration(domain)
    if partial and result.get("domain_age_days") is None:
        return partial
    result.update(source="WHOIS", retrieved_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        owner_status="UNKNOWN_OR_REDACTED", rdap_status="PARTIAL" if partial else "UNAVAILABLE",
        creation_date_source="whois_creation_date" if result.get("creation_date") else None,
        domain_age_months=round(result["domain_age_days"] / 30.4375, 2) if result.get("domain_age_days") is not None else None,
        domain_age_years=round(result["domain_age_days"] / 365.25, 2) if result.get("domain_age_days") is not None else None)
    return result
