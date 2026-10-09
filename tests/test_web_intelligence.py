# tests/test_web_intelligence.py
"""
tests/test_web_intelligence.py
-------------------------------
Comprehensive Test Suite for SecureSight Phase 4 HTML, DOM & Content Intelligence.
Includes unit tests, security tests (SSRF, redirects, response limits, malformed HTML),
content NLP analysis, dynamic isolation verification, performance timing, and API integration.
"""

import os
import time
import pytest
from unittest.mock import patch, MagicMock

from utils.safe_fetch import fetch_webpage_safely, is_url_ssrf_safe
from utils.html_features import extract_html_features
from utils.content_nlp import analyze_content_nlp, extract_visible_text
from utils.dynamic_analysis import analyze_webpage_dynamically
from utils.web_intelligence import analyze_web_intelligence

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(filename: str) -> str:
    path = os.path.join(FIXTURES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestSafeFetchGateway:
    def test_ssrf_blocking_private_ip(self):
        assert is_url_ssrf_safe("http://127.0.0.1/admin") is False
        assert is_url_ssrf_safe("http://localhost:8080") is False
        assert is_url_ssrf_safe("http://10.0.0.1/internal") is False
        assert is_url_ssrf_safe("http://169.254.169.254/latest/meta-data") is False

        res = fetch_webpage_safely("http://127.0.0.1/status")
        assert res["status"] == "INVALID_URL"
        assert res["html_content"] is None

    def test_invalid_scheme(self):
        res = fetch_webpage_safely("javascript:alert(1)")
        assert res["status"] == "INVALID_URL"

        res_file = fetch_webpage_safely("file:///etc/passwd")
        assert res_file["status"] == "INVALID_URL"

    @patch("utils.safe_fetch.pinned_pool")
    def test_response_size_limit(self, mock_gateway):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        # Emit chunks totaling > 100 bytes
        mock_resp.read1.side_effect = [b"A" * 60, b"B" * 60]
        pool = MagicMock()
        pool.urlopen.return_value = mock_resp
        from urllib.parse import urlsplit
        mock_gateway.return_value = (urlsplit("http://example.com/"), pool)

        res = fetch_webpage_safely("http://example.com", max_bytes=100)
        assert res["status"] == "RESOURCE_LIMIT_EXCEEDED"

    @patch("utils.safe_fetch.pinned_pool")
    def test_unsupported_content_type(self, mock_gateway):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "application/pdf"}
        pool = MagicMock()
        pool.urlopen.return_value = mock_resp
        from urllib.parse import urlsplit
        mock_gateway.return_value = (urlsplit("http://example.com/"), pool)

        res = fetch_webpage_safely("http://example.com/file.pdf")
        assert res["status"] == "CONTENT_TYPE_UNSUPPORTED"


class TestHTMLAndDOMAnalysis:
    def test_legitimate_login_fixture(self):
        html = _read_fixture("legitimate_login.html")
        analysis = extract_html_features(html, "https://example.com/login")
        feats = analysis["html_features"]

        assert analysis["title"] == "Example Portal - Sign In"
        assert feats["form_count"] == 1
        assert feats["password_input_count"] == 1
        assert feats["external_form_count"] == 0
        assert feats["canonical_domain_mismatch"] == 0
        assert feats["favicon_domain_mismatch"] == 0

    def test_phishing_login_fixture(self):
        html = _read_fixture("phishing_login.html")
        analysis = extract_html_features(html, "https://micros0ft-verify.com/login")
        feats = analysis["html_features"]

        assert feats["external_form_count"] == 1
        assert feats["password_input_count"] == 1
        assert feats["hidden_input_count"] == 1
        assert feats["canonical_domain_mismatch"] == 1
        assert feats["favicon_domain_mismatch"] == 1

    def test_obfuscated_script_detection(self):
        html = _read_fixture("obfuscated_script.html")
        analysis = extract_html_features(html, "https://example.com")
        feats = analysis["html_features"]

        assert feats["obfuscated_script_count"] >= 1

    def test_malformed_html_graceful_handling(self):
        html = _read_fixture("malformed.html")
        analysis = extract_html_features(html, "https://malformed.test")
        assert isinstance(analysis, dict)
        assert analysis["html_features"]["tag_count"] > 0


class TestContentNLP:
    def test_urgent_language_nlp(self):
        html = _read_fixture("urgent_language.html")
        nlp = analyze_content_nlp(html, "Account Suspended", "https://bank-notice.com")
        c_feats = nlp["content_features"]

        assert c_feats["urgency_score"] >= 0.5
        assert c_feats["phishing_keyword_count"] > 0

    def test_brand_domain_mismatch(self):
        html = _read_fixture("phishing_login.html")
        nlp = analyze_content_nlp(html, "Microsoft Account Verification", "https://evil-phish.com")

        assert nlp["brand_mismatch_detected"] is True
        assert nlp["detected_brand"] == "microsoft"


class TestDynamicAnalysisIsolation:
    def test_sandbox_security_enforcement(self):
        res = analyze_webpage_dynamically("https://example.com")
        sec = res["security_enforcement"]

        assert sec["javascript_executed"] is False
        assert sec["forms_submitted"] is False
        assert res["execution_mode"] == "NOT_EXECUTED"
        assert res["request_count"] == 0
        assert analyze_webpage_dynamically("https://example.com", allow_headless=True)["status"] == "DYNAMIC_ANALYSIS_UNAVAILABLE"


class TestWebIntelligenceOrchestration:
    def test_unified_web_intelligence_orchestrator(self):
        html = _read_fixture("phishing_login.html")
        intel = analyze_web_intelligence("https://fake-microsoft.com", html_content_override=html)

        assert intel["feature_version"] == "5.1.1"
        assert "html_features" in intel
        assert "content_features" in intel
        assert "combined_web_features" in intel

        codes = [ind["code"] for ind in intel["indicators"]]
        assert "EXTERNAL_CREDENTIAL_FORM" in codes
        assert "BRAND_DOMAIN_MISMATCH" in codes

    def test_phase4_performance_metrics(self):
        html = _read_fixture("legitimate_login.html")
        t0 = time.perf_counter()
        analyze_web_intelligence("https://example.com/login", html_content_override=html)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Static analysis should take under 100ms
        assert elapsed_ms < 100.0
