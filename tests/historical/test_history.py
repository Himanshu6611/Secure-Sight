import json
import time
from datetime import datetime, timezone, timedelta
import pytest
from app.brand.history import ObservationStore, analyze_history
from utils.rdap_intelligence import normalize_rdap, timestamp, lookup_rdap, CACHE, BOOTSTRAP_URL
from utils import rdap_intelligence
from app.security import json_fetch
from tests.redirect.test_redirects import transport
from utils import safe_fetch

NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


def rdap(**kwargs):
    return dict(objectClassName="domain", ldhName="example.com", events=[{"eventAction":"registration", "eventDate":"2000-01-01T00:00:00Z"}], **kwargs)


def snapshot(**kwargs):
    return dict(text_sha256="a"*64, dom_sha256="b"*64, script_sha256="c"*64, brand_ids=[], password_count=0, external_domains=[], **kwargs)


@pytest.mark.parametrize("value", [None, "garbage", "2020-01-01", "2100-01-01T00:00:00Z", "1900-01-01T00:00:00Z", "<script>", "2020-99-99T00:00:00Z"])
def test_invalid_registration_dates_unknown(value):
    data = rdap()
    data["events"] = [{"eventAction":"registration", "eventDate":value}]
    result = normalize_rdap(data, "example.com", NOW)
    assert result["domain_age_days"] is None
    assert result["is_recent_registration"] is False


def test_only_registration_event_defines_age():
    data = rdap()
    data["events"] = [{"eventAction":"last changed", "eventDate":"2020-01-01T00:00:00Z"}, {"eventAction":"expiration", "eventDate":"2030-01-01T00:00:00Z"}]
    result = normalize_rdap(data, "example.com", NOW)
    assert result["creation_date"] is None
    assert result["updated_date"] and result["expiration_date"]


def test_rdap_normalization_privacy_and_identity():
    data = rdap(entities=[{"roles":["registrant"], "vcardArray":["SECRET"]}, {"roles":["registrar"], "handle":"292"}],
        nameservers=[{"ldhName":"NS1.EXAMPLE.COM"}], secureDNS={"delegationSigned":True}, status=["active", "<script>"])
    result = normalize_rdap(data, "example.com", NOW)
    assert result["domain_age_days"] == (NOW-datetime(2000, 1, 1, tzinfo=timezone.utc)).days
    assert result["registrar"] == "292" and result["dnssec"] is True
    assert result["nameservers"] == ["ns1.example.com"]
    assert "SECRET" not in json.dumps(result)
    with pytest.raises(ValueError):
        normalize_rdap(data, "other.com", NOW)


def test_rdap_iana_discovery_and_cache_provenance(monkeypatch):
    CACHE.clear()
    calls = []
    def provider(url, deadline):
        calls.append(url)
        return {"services":[[["com"], ["https://rdap.example.net/"]]]} if url == BOOTSTRAP_URL else rdap()
    monkeypatch.setattr(rdap_intelligence, "fetch_json", provider)
    first = lookup_rdap("example.com")
    second = lookup_rdap("example.com")
    assert len(calls) == 2
    assert first["retrieved_at"] == second["retrieved_at"]
    assert first["discovery_source"] == BOOTSTRAP_URL
    CACHE.clear()


def test_bad_bootstrap_private_provider_rejected(monkeypatch):
    CACHE.clear()
    calls = []
    def provider(url, deadline):
        calls.append(url)
        return {"services":[[["com"], ["https://127.0.0.1/"]]]}
    monkeypatch.setattr(rdap_intelligence, "fetch_json", provider)
    with pytest.raises(ValueError):
        lookup_rdap("example.com")
    assert calls == [BOOTSTRAP_URL]
    CACHE.clear()


@pytest.mark.parametrize("spec", [
    {"headers":{"Content-Type":"text/html"}},
    {"headers":{"Content-Type":"application/json", "Content-Encoding":"gzip"}},
    {"headers":{"Content-Type":"application/json"}, "body":b"x"*131073},
    {"headers":{"Content-Type":"application/json"}, "body":b"[]"},
    {"status":302, "location":"http://127.0.0.1/"}])
def test_json_gateway_rejects_unsafe_responses(monkeypatch, spec):
    requests, responses, pools = transport(monkeypatch, {"https://rdap.example.com/":spec})
    monkeypatch.setattr(json_fetch, "pinned_pool", safe_fetch.pinned_pool)
    with pytest.raises(Exception):
        json_fetch.fetch_json("https://rdap.example.com/", time.monotonic()+2)
    assert len(requests) == 1
    assert all(p.closed for p in pools) and all(r.closed for r in responses)


def test_json_gateway_deadline_and_redirect_count(monkeypatch):
    requests, responses, pools = transport(monkeypatch, {"https://rdap.example.com/":{"status":302, "location":"/two"},
        "https://rdap.example.com/two":{"status":302, "location":"/three"}})
    monkeypatch.setattr(json_fetch, "pinned_pool", safe_fetch.pinned_pool)
    with pytest.raises(ValueError):
        json_fetch.fetch_json("https://rdap.example.com/", time.monotonic()+2)
    assert len(requests) == 2
    with pytest.raises(TimeoutError):
        json_fetch.fetch_json("https://rdap.example.com/", time.monotonic()-1)
    assert len(requests) == 2


def test_first_seen_separate_pages_and_retention():
    store = ObservationStore(2, 60)
    first = store.observe("https://example.com/about", snapshot(), NOW)
    second = store.observe("https://example.com/login", snapshot(), NOW+timedelta(seconds=10))
    assert first["page_first_seen"] == NOW.isoformat()
    assert second["page_first_seen"] != second["website_first_seen"]
    assert second["website_first_seen"] == NOW.isoformat()
    expired = store.observe("https://example.com/about", snapshot(), NOW+timedelta(seconds=100))
    assert expired["page_first_seen"] != first["page_first_seen"]
    for i in range(10):
        store.observe("https://example.com/"+str(i), snapshot(), NOW+timedelta(seconds=100))
    assert len(store.records) == 2


def test_sensitive_urls_not_indexed_and_no_raw_paths_stored():
    store = ObservationStore()
    result = store.observe("https://example.com/reset?token=SECRET", snapshot(), NOW)
    assert result["status"] == "UNAVAILABLE" and not store.records
    store.observe("https://example.com/SECRET", snapshot(), NOW)
    assert "SECRET" not in str(store.records)


def test_old_domain_recent_page_not_repurposing_and_changes_not_compromise():
    store = ObservationStore()
    inventory = {k:v for k,v in snapshot().items() if k.endswith("sha256")}
    web = {"html_features":{"password_input_count":0}, "resources":[]}
    domain = {"registration":{"domain_age_days":9000,"creation_date":"2000-01-01T00:00:00Z","source":"RDAP"}}
    first = analyze_history("https://example.com", inventory, web, domain, ["paypal"], store, NOW)
    assert first["page_age"]["created_at"] is None
    assert first["page_age"]["observed_age_days"] == 0
    assert not first["repurposing_context"]
    web["html_features"]["password_input_count"] = 1
    changed = analyze_history("https://example.com", inventory, web, domain, ["microsoft"], store, NOW+timedelta(days=.01))
    assert changed["repurposing_context"] and not changed["repurposing_confirmed"]
    assert "BRAND_CHANGED" in changed["changes"]
    assert changed["page_age"]["first_seen"] == first["page_age"]["first_seen"]


def test_current_dns_tls_metadata_differences_are_not_archive_history():
    store = ObservationStore()
    inventory = {k:v for k,v in snapshot().items() if k.endswith("sha256")}
    domain = {"dns":{"resolved_ips":["8.8.8.8"]}, "tls":{"not_after":"2026-12-01"}}
    analyze_history("https://example.com", inventory, {}, domain, [], store, NOW)
    domain["dns"]["resolved_ips"] = ["1.1.1.1"]
    domain["tls"]["not_after"] = "2027-01-01"
    result = analyze_history("https://example.com", inventory, {}, domain, [], store, NOW+timedelta(seconds=10))
    assert "DNS_OBSERVATION_CHANGED" in result["changes"] and "TLS_OBSERVATION_CHANGED" in result["changes"]
    assert result["providers"]["passive_dns"] == result["providers"]["certificate_history"] == "UNAVAILABLE"


def test_rdap_failure_uses_actual_whois_parser(monkeypatch):
    from utils import registration_intelligence
    monkeypatch.setattr(rdap_intelligence, "lookup_rdap", lambda _: (_ for _ in ()).throw(ValueError("unavailable")))
    monkeypatch.setattr(registration_intelligence, "whois_text", lambda _: 'Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\nCreation Date: 2000-01-01T00:00:00Z\nRegistry Expiry Date: 2030-01-01T00:00:00Z\nUpdated Date: 2025-01-01T00:00:00Z\nName Server: NS1.EXAMPLE.COM\n')
    result = registration_intelligence.get_domain_registration("example.com")
    assert result["source"] == "WHOIS" and result["domain_age_days"] > 1000
    assert result["updated_date"] and result["nameservers"] == ["ns1.example.com"]
    assert result["rdap_status"] == "UNAVAILABLE"


def test_partial_rdap_retained_if_whois_cannot_supply_creation(monkeypatch):
    from utils import registration_intelligence
    partial = normalize_rdap({"objectClassName":"domain","ldhName":"example.com"}, "example.com", NOW)
    monkeypatch.setattr(rdap_intelligence, "lookup_rdap", lambda _:partial)
    monkeypatch.setattr(registration_intelligence, "whois_text", lambda _:"")
    result = registration_intelligence.get_domain_registration("example.com")
    assert result["source"] == "RDAP" and result["domain_age_days"] is None


def test_whois_future_date_is_not_zero_day_registration(monkeypatch):
    from utils import registration_intelligence
    monkeypatch.setattr(rdap_intelligence, "lookup_rdap", lambda _: (_ for _ in ()).throw(ValueError("unavailable")))
    monkeypatch.setattr(registration_intelligence, "whois_text", lambda _: 'Domain Name: EXAMPLE.COM\nCreation Date: 2099-01-01T00:00:00Z\nRegistrar: Registrar\n')
    result = registration_intelligence.get_domain_registration("example.com")
    assert result["creation_date"] is None and result["domain_age_days"] is None
    assert not result["is_recent_registration"]


def test_json_gateway_success_and_no_authentication(monkeypatch):
    requests, responses, pools = transport(monkeypatch, {"https://rdap.example.com/":{"body":b'{"ok":true}',"headers":{"Content-Type":"application/json"}}})
    monkeypatch.setattr(json_fetch, "pinned_pool", safe_fetch.pinned_pool)
    assert json_fetch.fetch_json("https://rdap.example.com/", time.monotonic()+2) == {"ok":True}
    assert len(requests) == 1 and responses[0].closed and pools[0].closed
