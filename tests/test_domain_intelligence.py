# tests/test_domain_intelligence.py
"""
tests/test_domain_intelligence.py
----------------------------------
Comprehensive test suite for Phase 3: Domain & Reputation Intelligence Engine.
Covering domain extraction, DNS resolution, IP range classification, SSRF safety,
TLS cert inspection, WHOIS age parsing, reputation providers, and API endpoint integration.
"""

import pytest
from unittest.mock import patch

from utils.domain_extraction import normalize_domain, extract_domain_components
from utils.dns_intelligence import classify_ip_address, is_ssrf_safe_ip, resolve_dns
from utils.tls_intelligence import analyze_tls_certificate
from utils.registration_intelligence import get_domain_registration
from utils.reputation_providers import (
    LocalBlacklistProvider,
    MockReputationProvider,
    MultiProviderAggregator,
)
from utils.domain_cache import TTLMemoryCache
from utils.domain_intelligence import analyze_domain_intelligence


class TestDomainExtraction:
    def test_normalize_domain(self):
        assert normalize_domain("  EXAMPLE.COM. ") == "example.com"
        assert normalize_domain("sub.test.co.in") == "sub.test.co.in"

    def test_extract_domain_components(self):
        url = "https://login.example.co.in:8443/account?ref=1"
        res = extract_domain_components(url)
        assert res["original_hostname"] == "login.example.co.in"
        assert res["normalized_hostname"] == "login.example.co.in"
        assert res["registrable_domain"] == "example.co.in"
        assert res["subdomain"] == "login"
        assert res["tld"] == "co.in"
        assert res["port"] == 8443
        assert res["scheme"] == "https"

    def test_empty_url_raises(self):
        with pytest.raises(ValueError):
            extract_domain_components("")


class TestDNSAndSSRF:
    def test_classify_ip_address(self):
        assert classify_ip_address("127.0.0.1") == "LOOPBACK"
        assert classify_ip_address("10.0.0.1") == "PRIVATE"
        assert classify_ip_address("192.168.1.50") == "PRIVATE"
        assert classify_ip_address("8.8.8.8") == "PUBLIC"
        assert classify_ip_address("invalid.ip") == "INVALID"

    def test_ssrf_safety(self):
        assert is_ssrf_safe_ip("8.8.8.8") is True
        assert is_ssrf_safe_ip("127.0.0.1") is False
        assert is_ssrf_safe_ip("10.0.0.1") is False

    def test_resolve_dns_ip_input(self):
        res = resolve_dns("127.0.0.1")
        assert res["status"] == "SUCCESS"
        assert res["has_private_ip"] is True
        assert res["is_ssrf_safe"] is False

    @patch("dns.resolver.resolve")
    def test_resolve_dns_success(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = lambda domain, record, **kwargs: ["93.184.216.34"] if record == "A" else []
        res = resolve_dns("example.com")
        assert res["status"] == "SUCCESS"
        assert "93.184.216.34" in res["resolved_ips"]
        assert res["is_ssrf_safe"] is True

    @patch("dns.resolver.resolve")
    def test_resolve_dns_not_found(self, mock_getaddrinfo):
        import dns.resolver
        mock_getaddrinfo.side_effect = dns.resolver.NXDOMAIN()
        res = resolve_dns("nonexistent-domain-12345.xyz")
        assert res["status"] == "DOMAIN_NOT_FOUND"


class TestTLSIntelligence:
    def test_tls_invalid_hostname(self):
        res = analyze_tls_certificate("")
        assert res["status"] == "SSRF_BLOCKED"
        assert res["certificate_present"] is False

    @patch("socket.create_connection")
    def test_tls_timeout(self, mock_conn):
        import socket
        mock_conn.side_effect = socket.timeout("Connection timed out")
        res = analyze_tls_certificate("example.com", resolved_ips=["93.184.216.34"])
        assert res["status"] == "UNAVAILABLE"
        assert "timed out" in res["error_message"].lower()


class TestRegistrationIntelligence:
    def test_whois_missing_domain(self):
        res = get_domain_registration("")
        assert res["status"] == "UNAVAILABLE"
        assert res["domain_age_days"] is None


class TestReputationProviders:
    def test_local_blacklist_provider(self):
        provider = LocalBlacklistProvider()
        res = provider.lookup_domain("legitimate-example.com")
        assert res["status"] == "UNKNOWN"

    def test_multi_provider_aggregator(self):
        p1 = MockReputationProvider("mock_safe", "SAFE", 0.9)
        p2 = MockReputationProvider("mock_malicious", "MALICIOUS", 1.0)
        agg = MultiProviderAggregator([p1, p2])
        res = agg.aggregate_lookup("test.com")
        assert res["reputation_status"] == "MALICIOUS"
        assert res["provider_count"] == 2


class TestCache:
    def test_ttl_cache(self):
        cache = TTLMemoryCache(default_ttl=1.0)
        cache.set("key1", "val1")
        assert cache.get("key1") == "val1"
        cache.clear()
        assert cache.get("key1") is None


class TestDomainIntelligenceService:
    @patch("utils.domain_intelligence.resolve_dns")
    def test_analyze_domain_intelligence_flow(self, mock_dns):
        mock_dns.return_value = {
            "status": "SUCCESS",
            "resolved_ips": ["93.184.216.34"],
            "ipv4_addresses": ["93.184.216.34"],
            "ipv6_addresses": [],
            "ip_categories": ["PUBLIC"],
            "has_a_record": True,
            "has_aaaa_record": False,
            "has_private_ip": False,
            "is_ssrf_safe": True,
            "resolved_ip_count": 1,
        }

        intel = analyze_domain_intelligence("https://example.com/login", use_cache=False)
        assert intel["feature_version"] == "3.0"
        assert "domain_components" in intel
        assert intel["dns"]["status"] == "SUCCESS"
        assert intel["domain_features"]["dns_resolved"] == 1
        assert intel["domain_features"]["is_ssrf_safe"] == 1


class TestDomainIntelligenceAPI:
    def test_domain_intelligence_endpoint(self, client):
        resp = client.post("/api/v1/intelligence/domain", json={"url": "https://example.com"})
        assert resp.status_code == 200
        json_data = resp.get_json()
        assert "domain_intelligence" in json_data
        assert json_data["domain_intelligence"]["feature_version"] == "3.0"

    def test_domain_intelligence_missing_url(self, client):
        resp = client.post("/api/v1/intelligence/domain", json={})
        assert resp.status_code == 400
        assert resp.get_json()["error"]["code"] == "MISSING_URL"
