# tests/test_url_features.py
"""
tests/test_url_features.py
---------------------------
Comprehensive test suite for Phase 2: Advanced URL Feature Extraction & Indicator Engine.
"""

import pytest
from utils.url_features import (
    extract_advanced_url_features,
    shannon_entropy,
    levenshtein_distance,
    is_ip_address,
)
from utils.url_indicators import analyze_url_indicators


class TestURLFeatures:
    """Unit tests for URL feature extraction."""

    def test_empty_url_raises_value_error(self):
        with pytest.raises(ValueError):
            extract_advanced_url_features("")
        with pytest.raises(ValueError):
            extract_advanced_url_features("   ")

    def test_benign_url_features(self):
        url = "https://www.google.com/search?q=security"
        features = extract_advanced_url_features(url)
        assert features["url_len"] == len(url.replace("www.", "", 1))
        assert features["is_https"] == 1
        assert features["has_scheme"] == 1
        assert features["has_ip"] == 0
        assert features["is_shortener"] == 0
        assert features["query_params_count"] == 1
        assert features["subdomain_depth"] == 0
        assert isinstance(features["url_entropy"], float)

    def test_ip_hostname_features(self):
        url = "http://192.168.1.1/login.php"
        features = extract_advanced_url_features(url)
        assert features["has_ip"] == 1
        assert features["is_https"] == 0

    def test_url_shortener_detection(self):
        url = "https://bit.ly/3xY7zAb"
        features = extract_advanced_url_features(url)
        assert features["is_shortener"] == 1

    def test_suspicious_tld_detection(self):
        url = "http://free-bonus.xyz/claim"
        features = extract_advanced_url_features(url)
        assert features["is_suspicious_tld"] == 1

    def test_brand_in_subdomain(self):
        url = "https://paypal.verify-account.com/login"
        features = extract_advanced_url_features(url)
        assert features["brand_in_subdomain"] == 1

    def test_brand_in_path(self):
        url = "https://example.com/login/paypal/verify"
        features = extract_advanced_url_features(url)
        assert features["brand_in_path"] == 1

    def test_typosquatting_distance(self):
        # 'paypa1' domain has Levenshtein distance 1 from 'paypal'
        url = "http://www.paypa1.com/login"
        features = extract_advanced_url_features(url)
        assert features["min_brand_distance"] <= 2

    def test_at_symbol_detection(self):
        url = "http://google.com@phishing-site.com/auth"
        features = extract_advanced_url_features(url)
        assert features["has_at_symbol"] == 1
        assert features["at_count"] == 1

    def test_non_standard_port(self):
        url = "http://example.com:8080/admin"
        features = extract_advanced_url_features(url)
        assert features["has_port"] == 1
        assert features["is_non_standard_port"] == 1


class TestURLIndicators:
    """Unit tests for URL suspicious indicator engine."""

    def test_ip_as_hostname_indicator(self):
        url = "http://192.168.1.1/admin"
        res = analyze_url_indicators(url)
        codes = [i["code"] for i in res["indicators"]]
        assert "IP_AS_HOSTNAME" in codes
        assert res["total_risk_score"] >= 25.0

    def test_phishing_combination_indicators(self):
        url = "http://paypal.verify-account.xyz@192.168.1.1/login"
        res = analyze_url_indicators(url)
        assert res["risk_level"] in ("HIGH", "CRITICAL")
        codes = [i["code"] for i in res["indicators"]]
        assert "IP_AS_HOSTNAME" in codes
        # Query text cannot change the hostname's TLD.
        assert "HIGH_RISK_TLD" not in codes
        assert "AT_SYMBOL_OBFUSCATION" in codes

    def test_benign_url_low_risk(self):
        url = "https://www.github.com"
        res = analyze_url_indicators(url)
        assert res["risk_level"] == "LOW"
        assert res["total_risk_score"] < 15.0


class TestAPIEndpoint:
    """Integration test for POST /api/v1/features/url endpoint."""

    def test_features_endpoint_success(self, client):
        resp = client.post("/api/v1/features/url", json={"url": "https://paypal.com.verify-auth.xyz/login"})
        assert resp.status_code == 200
        json_data = resp.get_json()
        assert "features" in json_data
        assert "indicators" in json_data
        assert json_data["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert json_data["features"]["brand_in_subdomain"] == 1

    def test_features_endpoint_missing_url(self, client):
        resp = client.post("/api/v1/features/url", json={})
        assert resp.status_code == 400
        json_data = resp.get_json()
        assert json_data["error"]["code"] == "MISSING_URL"
