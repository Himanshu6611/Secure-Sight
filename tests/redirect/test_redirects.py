import io
import json
from pathlib import Path
from urllib.parse import urlsplit
import pytest
import dns.resolver
import urllib3
from app.security.urls import validate_url
from app.behavior.privacy import normalize_destination, redact_url
from app.behavior.analyzer import analyze_behavior
from utils import safe_fetch


class Response:
    def __init__(self, status=200, location=None, body=b"<html><title>Example</title></html>", headers=None):
        self.status = status
        self.headers = {"Content-Type": "text/html", **(headers or {})}
        if location is not None:
            self.headers["Location"] = location
        self.body = io.BytesIO(body)
        self.connection = None
        self.closed = False
    def read1(self, count, decode_content=False):
        return self.body.read(count)
    def close(self):
        self.closed = True


class Pool:
    def __init__(self, response, requests, **kwargs):
        self.host = kwargs.get("host", "8.8.8.8")
        self.response = response
        self.requests = requests
        self.closed = False
    def urlopen(self, method, path, **kwargs):
        assert method == "GET" and kwargs["redirect"] is False and kwargs["retries"] is False
        assert "Cookie" not in kwargs["headers"] and "Authorization" not in kwargs["headers"]
        self.requests.append({"path": path, "headers": kwargs["headers"], "host": self.host})
        return self.response
    def close(self):
        self.closed = True


def transport(monkeypatch, routes):
    requests, responses, pools = [], [], []
    def gateway(url, timeout):
        canonical = normalize_destination(url)
        spec = routes[canonical]
        response = spec if isinstance(spec, Response) else Response(**spec)
        pool = Pool(response, requests)
        responses.append(response)
        pools.append(pool)
        return urlsplit(validate_url(url)), pool
    monkeypatch.setattr(safe_fetch, "pinned_pool", gateway)
    return requests, responses, pools


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_http_redirects_and_cleanup(monkeypatch, status):
    requests, responses, pools = transport(monkeypatch, {
        "https://example.com/": {"status":status, "location":"/login"}, "https://example.com/login": {}})
    result = safe_fetch.fetch_webpage_safely("https://example.com/")
    assert result["status"] == "SUCCESS" and result["redirect_count"] == 1
    hop = result["redirect_chain"][0]
    assert hop["status_code"] == status and hop["same_domain"] is True and hop["followed"] is True
    assert len(requests) == 2
    assert all(response.closed for response in responses) and all(pool.closed for pool in pools)


@pytest.mark.parametrize("initial,target,key", [("http://example.com/","https://example.com/","http_to_https"),
    ("https://example.com/","http://example.net/","https_to_http")])
def test_scheme_transitions(monkeypatch, initial, target, key):
    transport(monkeypatch, {initial:{"status":302,"location":target}, target:{}})
    result = safe_fetch.fetch_webpage_safely(initial)
    assert result["redirect_chain"][0][key] is True
    behavior = analyze_behavior(initial, result, {"status":"ANALYZED", "destinations":[]})
    assert behavior["features"][key] == 1


def test_public_suffix_and_subdomain_change(monkeypatch):
    transport(monkeypatch, {"https://a.example.co.uk/":{"status":302,"location":"https://b.example.co.uk/"}, "https://b.example.co.uk/":{}})
    result = safe_fetch.fetch_webpage_safely("https://a.example.co.uk/")
    hop = result["redirect_chain"][0]
    assert hop["same_domain"] is True and hop["subdomain_changed"] is True
    assert hop["source_domain"] == "example.co.uk"


@pytest.mark.parametrize("loop", ["https://example.com/", "https://example.com/#different"])
def test_loop_duplicate_and_fragment_normalization(monkeypatch, loop):
    requests, _, _ = transport(monkeypatch, {"https://example.com/":{"status":302,"location":"/next"},
        "https://example.com/next":{"status":302,"location":loop}})
    result = safe_fetch.fetch_webpage_safely("https://example.com/")
    assert result["status"] == "REDIRECT_LOOP" and len(requests) == 2
    assert result["redirect_loop_detected"] is True
    behavior = analyze_behavior("https://example.com/", result)
    codes = {r["indicator"] for r in behavior["indicators"]}
    assert {"BEHAVIOR_REDIRECT_LOOP", "BEHAVIOR_DUPLICATE_DESTINATION"} <= codes
    assert behavior["final_url"] is None


def test_redirect_bomb_stops_at_configured_limit(monkeypatch):
    routes = {f"https://example.com/{i}":{"status":302,"location":f"/{i+1}"} for i in range(1000)}
    requests, _, _ = transport(monkeypatch, routes)
    result = safe_fetch.fetch_webpage_safely("https://example.com/0")
    assert result["status"] == "REDIRECT_LIMIT_EXCEEDED"
    assert len(requests) == safe_fetch.MAX_REDIRECTS+1
    assert len(result["redirect_chain"]) == safe_fetch.MAX_REDIRECTS+1


@pytest.mark.parametrize("destination", ["http://127.0.0.1/", "http://10.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://[::1]/",
    "http://[fd00::1]/", "http://localhost/", "http://server.internal/", "http://100.100.100.200/", "file:///etc/passwd", "javascript:alert(1)", "http://example.com:8080/"])
def test_private_metadata_and_invalid_redirects_never_contacted(monkeypatch, destination):
    requests, _, _ = transport(monkeypatch, {"https://example.com/":{"status":302,"location":destination}})
    result = safe_fetch.fetch_webpage_safely("https://example.com/")
    assert result["status"] == "SSRF_BLOCKED" and len(requests) == 1
    assert result["redirect_chain"][0]["followed"] is False
    assert destination not in json.dumps(result["redirect_chain"])


def test_dns_rebinding_revalidated_and_socket_pinned(monkeypatch):
    calls, requests = [], []
    def resolve(host, record, **kwargs):
        if record == "AAAA":
            raise dns.resolver.NoAnswer()
        calls.append(host)
        return ["8.8.8.8"] if len(calls) == 1 else ["127.0.0.1"]
    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    pools = []
    def http_pool(**kwargs):
        pool = Pool(Response(status=302, location="/?next=1"), requests, **kwargs)
        pools.append(pool)
        return pool
    monkeypatch.setattr(urllib3, "HTTPConnectionPool", http_pool)
    result = safe_fetch.fetch_webpage_safely("http://example.com/")
    assert result["status"] == "SSRF_BLOCKED"
    assert len(calls) == 2 and len(pools) == 1
    assert requests[0]["host"] == "8.8.8.8"


@pytest.mark.parametrize("error,status", [(dns.resolver.NXDOMAIN(),"DNS_FAILED"), (TimeoutError(),"TIMEOUT"), (OSError(),"DNS_FAILED")])
def test_transport_failures(monkeypatch, error, status):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(safe_fetch, "pinned_pool", fail)
    result = safe_fetch.fetch_webpage_safely("https://example.com/")
    assert result["status"] == status and result["html_content"] is None


@pytest.mark.parametrize("headers,body,status", [({"Content-Length":"1000"}, b"small", "RESOURCE_LIMIT_EXCEEDED"),
    ({},b"x"*101,"RESOURCE_LIMIT_EXCEEDED"), ({"Content-Encoding":"gzip"},b"compressed","CONTENT_TYPE_UNSUPPORTED"),
    ({"Content-Type":"application/octet-stream"},b"download","CONTENT_TYPE_UNSUPPORTED")])
def test_response_bombs_and_downloads(monkeypatch, headers, body, status):
    _, responses, pools = transport(monkeypatch, {"https://example.com/":{"headers":headers,"body":body}})
    result = safe_fetch.fetch_webpage_safely("https://example.com/", max_bytes=100)
    assert result["status"] == status and result["html_content"] is None
    assert responses[0].closed and pools[0].closed


def test_total_deadline_on_slow_body(monkeypatch):
    clock = [0.]
    monkeypatch.setattr(safe_fetch.time, "monotonic", lambda: clock[0])
    class Slow(Response):
        def read1(self, *args, **kwargs):
            clock[0] = 7.
            return b"x"
    transport(monkeypatch, {"https://example.com/":Slow()})
    assert safe_fetch.fetch_webpage_safely("https://example.com/")["status"] == "TIMEOUT"


def test_query_path_and_fragment_privacy(monkeypatch):
    initial = "https://example.com/reset/SECRET?Token=secret&unlisted=private#hidden"
    target = "https://example.net/login/SECRET2?code=private2"
    transport(monkeypatch, {normalize_destination(initial):{"status":302,"location":target}, normalize_destination(target):{}})
    result = safe_fetch.fetch_webpage_safely(initial)
    behavior = analyze_behavior(initial, result, {"status":"ANALYZED","destinations":[]})
    public = json.dumps(behavior)
    for secret in ("SECRET", "private", "hidden", "unlisted", "Token"):
        assert secret not in public
    assert "query-redacted" in public
    assert behavior["initial_final_comparison"]["query_changed"] is True


@pytest.mark.parametrize("fixture", ["same_domain", "cross_domain", "loop", "shortener", "http_downgrade", "excessive_chain", "failed_redirect"])
def test_frozen_redirect_fixtures(monkeypatch, fixture):
    data = json.loads((Path(__file__).parents[1]/"fixtures"/"redirect"/(fixture+".json")).read_text())
    transport(monkeypatch, data["routes"])
    result = safe_fetch.fetch_webpage_safely(data["initial_url"])
    assert result["status"] == data["expected_status"]
