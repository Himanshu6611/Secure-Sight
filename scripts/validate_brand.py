"""Controlled Phase 9 benchmarks. No production accuracy or latency claim."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import json
import statistics
import time
import tracemalloc
from unittest.mock import patch
from urllib.parse import urlsplit
from app.brand.analyzer import analyze_brand
from app.brand.history import ObservationStore
from app.brand.crawl import crawl_site
from app.brand.similarity import compare
from utils.html_features import extract_html_features
from utils.web_intelligence import analyze_web_intelligence
from utils.rdap_intelligence import normalize_rdap
from tests.redirect.test_redirects import Response, Pool
from app import create_app

URL = "https://example.com/"
HTML = '<title>Example portal</title><a href="/login">Login</a><a href="/about">About</a>'
WEB = analyze_web_intelligence(URL, HTML)
DOMAIN = dict(dns=dict(status="SUCCESS", is_ssrf_safe=True), tls=dict(status="VALID",certificate_valid=True),
    registration=dict(status="AVAILABLE",domain_age_days=1000), reputation=dict(reputation_status="UNKNOWN"))
RDAP = dict(objectClassName="domain", ldhName="example.com", events=[dict(eventAction="registration",eventDate="2000-01-01T00:00:00Z")])


def benchmark(fn, count=100):
    samples = []
    for _ in range(count):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter()-started)*1000)
    ordered = sorted(samples)
    return dict(iterations=count, median_ms=statistics.median(samples), p95_ms=ordered[int(.95*(count-1))], p95_method="nearest lower order statistic")


def main():
    output = dict(scope="Controlled fixture timings on this machine; not production network latency or representative accuracy.")
    output["inventory"] = benchmark(lambda:extract_html_features(HTML, URL))
    output["similarity"] = benchmark(lambda:compare("paypa1", "paypal"))
    output["rdap_normalization"] = benchmark(lambda:normalize_rdap(RDAP, "example.com"))
    store = ObservationStore()
    output["brand_history_without_crawl"] = benchmark(lambda:analyze_brand(URL, WEB, DOMAIN, enable_crawl=False, store=store))
    requests = []
    def gateway(url, timeout):
        parsed = urlsplit(url)
        response = Response(status=404) if parsed.path == "/robots.txt" else Response(body=HTML.encode())
        return parsed, Pool(response, requests)
    with patch("utils.safe_fetch.pinned_pool", gateway):
        output["controlled_crawl"] = benchmark(lambda:crawl_site(URL, WEB["_brand_inventory"], WEB["fetch_summary"]))
        app = create_app(dict(TESTING=True, SITE_URL="http://localhost:5000", RATELIMIT_STORAGE_URI="memory://", SCAN_RATE_LIMIT="1000 per minute"))
        client = app.test_client()
        app.logger.disabled = True
        with patch("app.services.scans.analyze_domain_intelligence", return_value=DOMAIN), patch("app.services.scans.analyze_web_intelligence", side_effect=lambda _:analyze_web_intelligence(URL, HTML)):
            status_codes = []
            def request():
                response = client.post("/api/v1/scan", json={"url":URL})
                status_codes.append(response.status_code)
                if response.status_code != 200:
                    raise RuntimeError("Benchmark scan failed")
            tracemalloc.start()
            output["controlled_integrated_api"] = benchmark(request, 10)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            output["python_traced_peak_bytes"] = peak
            output["api_status_codes"] = status_codes
    output["network_provider_timings"] = "Measured separately by live smoke; fixture timings do not measure RDAP/WHOIS/DNS/TLS network."
    target = Path("reports/remediation_20261008/phase9_performance.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(output, indent=2)+"\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
