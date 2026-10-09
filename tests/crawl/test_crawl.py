import json
import pytest
from app.brand.crawl import crawl_site
from app.brand.config import load_config
from app.brand.analyzer import analyze_brand
from app.brand.history import ObservationStore
from utils.web_intelligence import analyze_web_intelligence
from tests.redirect.test_redirects import transport

ROOT = "https://example.com/"


def root_web():
    return analyze_web_intelligence(ROOT, '<title>Example</title><a href="/login">Login</a><a href="/about">About</a><a href="https://other.example/support">external</a><a href="/reset?token=SECRET">reset</a>')


def test_priority_root_reuse_and_no_external_or_token_fetch(monkeypatch):
    requests, responses, pools = transport(monkeypatch, {ROOT+"robots.txt":{"status":404},
        ROOT+"login":{"body":b'<title>PayPal</title><h1>PayPal login</h1><input type="password">'}, ROOT+"about":{}})
    web = root_web()
    result = analyze_brand(ROOT, web, {}, store=ObservationStore())
    assert [r["path"] for r in requests] == ["/robots.txt", "/login", "/about"]
    assert result["crawl"]["pages"][0]["reused_root"]
    assert result["inspected_brand_ids"] == ["paypal"]
    assert "SECRET" not in json.dumps(result)
    assert all(p.closed for p in pools) and all(r.closed for r in responses)


def test_depth_two_static_crawl_stays_within_hostname(monkeypatch):
    config = load_config()
    config.update(max_pages=8, max_depth=2, max_requests=16)
    requests, _, _ = transport(monkeypatch, {
        ROOT+"robots.txt":{"status":404},
        ROOT+"login":{"body":b'<a href="/security">Security</a>'},
        ROOT+"security":{"body":b'<title>Security</title>'},
        ROOT+"about":{},
    })
    web = root_web()
    result = crawl_site(ROOT, web["_brand_inventory"], web["fetch_summary"], config)
    assert [request["path"] for request in requests] == ["/robots.txt", "/login", "/security", "/about"]
    assert any(page["depth"] == 2 and page["status"] == "ANALYZED" for page in result["pages"])
    assert result["same_site_only"] is True


@pytest.mark.parametrize("destination", ["https://other.example/login", "https://login.example.com/login", "http://127.0.0.1/admin", "http://169.254.169.254/metadata", "file:///etc/passwd"])
def test_child_redirect_blocks_before_contact(monkeypatch, destination):
    requests, _, _ = transport(monkeypatch, {ROOT+"robots.txt":{"status":404}, ROOT+"login":{"status":302,"location":destination}, ROOT+"about":{}})
    web = root_web()
    result = crawl_site(ROOT, web["_brand_inventory"], web["fetch_summary"])
    assert len(requests) == 3
    assert result["pages"][1]["status"] in {"CRAWL_SCOPE_BLOCKED", "SSRF_BLOCKED"}


def test_child_page_first_observations_are_recorded(monkeypatch):
    transport(monkeypatch, {ROOT+"robots.txt":{"status":404}, ROOT+"login":{}, ROOT+"about":{}})
    store = ObservationStore()
    result = analyze_brand(ROOT, root_web(), {}, store=store)
    assert len(store.records) == 3
    assert result["crawl"]["pages"][1]["page_age"]["first_seen"]
    assert result["crawl"]["pages"][1]["page_age"]["created_at"] is None


@pytest.mark.parametrize("robots,paths", [("User-agent: *\nDisallow: /login", ["/robots.txt", "/about"]),
    ("User-agent: *\nDisallow: /", ["/robots.txt"]), ("User-agent: *\nCrawl-delay: 5", ["/robots.txt"])])
def test_robots_rules_honored(monkeypatch, robots, paths):
    requests, _, _ = transport(monkeypatch, {ROOT+"robots.txt":{"headers":{"Content-Type":"text/plain"},"body":robots.encode()}, ROOT+"about":{}})
    web = root_web()
    result = crawl_site(ROOT, web["_brand_inventory"], web["fetch_summary"])
    assert [r["path"] for r in requests] == paths
    assert result["robots_status"] == "AVAILABLE"


def test_unknown_robots_stops_children(monkeypatch):
    requests, _, _ = transport(monkeypatch, {ROOT+"robots.txt":{"status":503}})
    web = root_web()
    result = crawl_site(ROOT, web["_brand_inventory"], web["fetch_summary"])
    assert len(requests) == 1 and result["stop_reason"] == "ROBOTS_UNAVAILABLE"


@pytest.mark.parametrize("limit,value", [("max_requests",1), ("max_pages",1), ("max_depth",0), ("max_total_bytes",1024)])
def test_cumulative_limits(monkeypatch, limit, value):
    requests, _, _ = transport(monkeypatch, {ROOT+"robots.txt":{"status":404}, ROOT+"login":{}, ROOT+"about":{}})
    web = root_web()
    config = load_config()
    config[limit] = value
    summary = {**web["fetch_summary"], "request_count":1, "response_bytes":1024}
    result = crawl_site(ROOT, web["_brand_inventory"], summary, config)
    assert result["request_count"] <= config["max_requests"]
    assert len(result["pages"]) <= config["max_pages"]
    if limit in {"max_requests", "max_total_bytes", "max_depth", "max_pages"}:
        assert not requests


def test_global_deadline_includes_root_elapsed(monkeypatch):
    requests, _, _ = transport(monkeypatch, {})
    web = root_web()
    result = crawl_site(ROOT, web["_brand_inventory"], {**web["fetch_summary"], "elapsed_ms":13000})
    assert not requests
    assert result["stop_reason"] == "RESOURCE_LIMIT_EXCEEDED"


def test_duplicate_links_and_private_hosts_are_not_contacted(monkeypatch):
    requests, _, _ = transport(monkeypatch, {ROOT+"robots.txt":{"status":404}, ROOT+"login":{}})
    web = analyze_web_intelligence(ROOT, '<a href="/login">1</a><a href="/login#x">2</a><a href="/login">3</a><a href="http://localhost">private</a><a href="https://login.example.com">subdomain</a>')
    result = crawl_site(ROOT, web["_brand_inventory"], web["fetch_summary"])
    assert len(requests) == 2
    assert result["same_site_only"] is True


def test_versioned_api_and_public_privacy(client, monkeypatch):
    from app.services import scans
    monkeypatch.setattr(scans, "analyze_web_intelligence", lambda url: root_web())
    transport(monkeypatch, {ROOT+"robots.txt":{"status":404}, ROOT+"login":{}, ROOT+"about":{}})
    response = client.post("/api/v1/scan", json={"url":ROOT, "email_context":{"sender_domain":"mailer.example"}})
    assert response.status_code == 200
    body = response.json
    assert body["brand_feature_version"] == "9.0.0"
    assert body["feature_schema_version"] == "5.1.1" and len(body["feature_vector"]) == 97
    assert "_brand_inventory" not in body["web_intelligence"]
    assert "_children" not in body["brand_intelligence"]["crawl"]


@pytest.mark.parametrize("email", [{"sender_domain":"a/b"},{"claimed_brand":"invented"},{"cookie":"secret"}])
def test_bad_email_context_returns_400(client, email):
    assert client.post("/api/v1/scan", json={"url":ROOT,"email_context":email}).status_code == 400
