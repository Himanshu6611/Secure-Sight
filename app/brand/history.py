"""Bounded process-local first observations, not a global web archive.

Only hashes, registry brand IDs and counts are stored. Restarts/retention expiry
lose history; absence cannot prove a site or page was recently created.
"""
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import threading
from urllib.parse import urlsplit
from app.brand.config import load_config


class ObservationStore:
    def __init__(self, max_entries=512, retention_seconds=86400):
        self.max_entries = max_entries
        self.retention_seconds = retention_seconds
        self.records = OrderedDict()
        self.lock = threading.Lock()

    def observe(self, url, snapshot, now=None):
        now = now or datetime.now(timezone.utc)
        parsed = urlsplit(url)
        # URLs containing query credentials/tracking tokens are not indexed.
        if parsed.query or parsed.fragment:
            return dict(status="UNAVAILABLE", reason="SENSITIVE_URL_NOT_INDEXED", snapshots=[], website_first_seen=None, page_first_seen=None)
        site = hashlib.sha256((parsed.hostname or "").encode()).hexdigest()
        key = hashlib.sha256((site + (parsed.path or "/")).encode()).hexdigest()
        safe = {k: deepcopy(snapshot[k]) for k in ("text_sha256", "dom_sha256", "script_sha256", "brand_ids", "password_count", "external_domains")}
        for field in ("dns_sha256", "tls_sha256", "registration_sha256"):
            if field in snapshot:
                safe[field] = snapshot[field]
        safe.update(observed_at=now.isoformat(), source="SECURESIGHT_INTERNAL_OBSERVATION", confidence=.5)
        with self.lock:
            for expired in [k for k, r in self.records.items() if (now-r["last_seen"]).total_seconds() > self.retention_seconds]:
                del self.records[expired]
            record = self.records.get(key)
            if record and record["last_seen"] > now:
                # A clock rollback/backdated analysis must not consume future history.
                return dict(status="UNAVAILABLE", reason="FUTURE_OBSERVATION_EXCLUDED", snapshots=[],
                            website_first_seen=None, page_first_seen=None)
            previous = deepcopy(record["snapshots"]) if record else []
            site_dates = [r["first_seen"] for r in self.records.values() if r["site"] == site and r["first_seen"] <= now]
            website_first = min(site_dates + [now])
            if record is None:
                record = dict(site=site, first_seen=now, last_seen=now, snapshots=[])
            record["last_seen"] = now
            # Multiple scans within the same second do not create a change event.
            if not record["snapshots"] or safe != record["snapshots"][-1]:
                record["snapshots"].append(safe)
            record["snapshots"] = record["snapshots"][-8:]
            self.records[key] = record
            self.records.move_to_end(key)
            while len(self.records) > self.max_entries:
                self.records.popitem(last=False)
            return dict(status="PARTIAL", reason="PROCESS_LOCAL_HISTORY_ONLY", snapshots=previous,
                website_first_seen=website_first.isoformat(), page_first_seen=record["first_seen"].isoformat())

    def clear(self):
        with self.lock:
            self.records.clear()


_CONFIG = load_config()
STORE = ObservationStore(_CONFIG["history_max_entries"], _CONFIG["history_retention_seconds"])


def analyze_history(url, inventory, web, domain, brand_ids, store=None, now=None):
    now = now or datetime.now(timezone.utc)
    registration = domain.get("registration", {})
    snapshot = {k: inventory[k] for k in ("text_sha256", "dom_sha256", "script_sha256")}
    snapshot.update(brand_ids=sorted(brand_ids), password_count=web.get("html_features", {}).get("password_input_count", 0),
        external_domains=sorted({r.get("domain") for r in web.get("resources", []) if r.get("is_external") and r.get("domain")})[:32])
    for key, fields in (("dns", ("resolved_ips",)), ("tls", ("not_before", "not_after", "issuer")), ("registration", ("registrar", "nameservers"))):
        observed = domain.get(key, {})
        snapshot[key + "_sha256"] = hashlib.sha256(json.dumps({f: observed.get(f) for f in fields}, sort_keys=True, default=str).encode()).hexdigest()
    record = (store or STORE).observe(url, snapshot, now)
    previous = record.pop("snapshots")
    changes = []
    if previous:
        old = previous[-1]
        for field, code in (("text_sha256", "TEXT_CHANGED"), ("dom_sha256", "DOM_CHANGED"), ("script_sha256", "SCRIPTS_CHANGED"),
                            ("brand_ids", "BRAND_CHANGED"), ("password_count", "CREDENTIAL_FORMS_CHANGED"), ("external_domains", "EXTERNAL_DOMAINS_CHANGED")):
            if old.get(field) != snapshot[field]:
                changes.append(code)
        for field, code in (("dns_sha256", "DNS_OBSERVATION_CHANGED"), ("tls_sha256", "TLS_OBSERVATION_CHANGED"), ("registration_sha256", "REGISTRATION_METADATA_CHANGED")):
            if field in old and old[field] != snapshot[field]:
                changes.append(code)
    timeline = []
    if registration.get("creation_date"):
        timeline.append(dict(event="DOMAIN_REGISTRATION", event_type="KNOWN_PROVIDER_EVENT", date=registration["creation_date"],
            source=registration.get("source", "REGISTRATION_PROVIDER"), confidence=.8))
    for field, event in (("website_first_seen", "WEBSITE_FIRST_OBSERVED"), ("page_first_seen", "PAGE_FIRST_OBSERVED")):
        if record[field]:
            timeline.append(dict(event=event, event_type="FIRST_OBSERVED", date=record[field], source="SECURESIGHT_INTERNAL_OBSERVATION", confidence=.5))
    for change in changes:
        timeline.append(dict(event=change, event_type="OBSERVED_DIFFERENCE", date=now.isoformat(), source="SECURESIGHT_INTERNAL_OBSERVATION", confidence=.5))
    def age(field):
        value = record[field]
        return dict(status="PARTIAL" if value else "UNAVAILABLE", first_seen=value, created_at=None,
            observed_age_days=(now-datetime.fromisoformat(value)).days if value else None,
            source="SECURESIGHT_INTERNAL_OBSERVATION" if value else None, retrieved_at=now.isoformat(),
            confidence=.5 if value else 0, interpretation="First seen by this process; not creation or first appearance on the Internet.")
    old_domain = type(registration.get("domain_age_days")) is int and registration["domain_age_days"] >= 365
    return dict(**record, source="SECURESIGHT_INTERNAL_OBSERVATION", retrieved_at=now.isoformat(),
        observed_at=now.isoformat(), data_age_seconds=0, observation_count=len(previous) + 1,
        changes=changes, website_age=age("website_first_seen"), page_age=age("page_first_seen"), timeline=timeline,
        repurposing_context=bool(old_domain and "BRAND_CHANGED" in changes and "CREDENTIAL_FORMS_CHANGED" in changes),
        repurposing_confirmed=False,
        providers={"web_archive":"UNAVAILABLE", "certificate_history":"UNAVAILABLE", "passive_dns":"UNAVAILABLE", "ownership_history":"UNAVAILABLE"})
