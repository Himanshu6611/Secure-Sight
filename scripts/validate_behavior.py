"""Controlled redirect replay and actual configured-capacity load measurements."""
import json
import statistics
import sys
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app
from app.behavior.privacy import normalize_destination
from app.risk.config import config_digest
from tests.redirect.test_redirects import Response, Pool
from tests.explanation.test_engine import observations
from utils.safe_fetch import fetch_webpage_safely


def distribution(samples):
    ordered = sorted(samples)
    rank = .95*(len(ordered)-1)
    index, fraction = int(rank), rank-int(rank)
    p95 = ordered[index]*(1-fraction)+ordered[min(index+1,len(ordered)-1)]*fraction
    return {"median_ms":round(statistics.median(ordered),6), "p95_ms":round(p95,6)}


def main():
    context = observations(False, .02, "SAFE")
    app = create_app({"APP_ENV":"testing", "TESTING":True, "SITE_URL":"http://localhost:5000",
                      "TRUSTED_HOSTS":["localhost"], "RATELIMIT_STORAGE_URI":"memory://", "ALLOWED_ORIGINS":[]})
    app.logger.disabled = True
    requests = []
    def gateway(url, timeout):
        response = Response(status=302,location="https://example.net/") if normalize_destination(url) == "http://example.com/" else Response()
        return urlsplit(url), Pool(response, requests)
    folder = Path("reports/phase8_20261008")
    folder.mkdir(parents=True, exist_ok=True)
    durations = []
    with patch("utils.safe_fetch.pinned_pool", gateway), patch("app.services.scans.analyze_domain_intelligence", return_value=context["domain_intelligence"]):
        for _ in range(100):
            start = time.perf_counter()
            result = fetch_webpage_safely("http://example.com/")
            durations.append((time.perf_counter()-start)*1000)
            assert result["status"] == "SUCCESS" and result["redirect_count"] == 1
        loads = []
        serial = [0]
        def scan(_):
            serial[0] += 1
            address = "198.51.100."+str(serial[0])
            with app.test_client() as client:
                start = time.perf_counter()
                response = client.post("/api/v1/scan",json={"url":"http://example.com/"}, environ_overrides={"REMOTE_ADDR":address})
                elapsed = (time.perf_counter()-start)*1000
                if response.status_code == 200:
                    assert response.json["behavior_intelligence"]["status"] == "ANALYZED"
                    assert response.json["explanation"]["behavioral_reasons"]
                    assert response.json["verdict"] != "PHISHING"
                return response.status_code, elapsed
        tracemalloc.start()
        for users in (1, 10, 50):
            cpu_start, wall_start = time.process_time(), time.perf_counter()
            with ThreadPoolExecutor(max_workers=users) as executor:
                values = list(executor.map(scan, range(users)))
            loads.append({"concurrent_clients":users, "http_status_counts":{str(code):sum(v[0]==code for v in values) for code in sorted({v[0] for v in values})},
                "latency_all_responses":distribution([v[1] for v in values]),
                "accepted_scan_latency":distribution([v[1] for v in values if v[0]==200]),
                "rejected_response_latency":distribution([v[1] for v in values if v[0]!=200]) if any(v[0]!=200 for v in values) else None,
                "wall_ms":round((time.perf_counter()-wall_start)*1000,3),
                "process_cpu_ms":round((time.process_time()-cpu_start)*1000,3)})
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    report = {"behavior_version":"8.0.0", "scoring_version":app.extensions["risk_engine"].config["version"],
        "scoring_config_sha256":config_digest(app.extensions["risk_engine"].config),
        "explanation_version":app.extensions["explanation_engine"].registry["version"],
        "scope":"Controlled pinned-gateway fixtures; CPU/memory include local model and API; no real network accuracy/SLA claim",
        "redirect_replays":100, "redirect_latency":distribution(durations), "scan_capacity":app.config["MAX_CONCURRENT_SCANS"],
        "load_tests":loads, "peak_python_allocated_bytes":peak,
        "dynamic_browser":{"status":"NOT_IMPLEMENTED", "startup_ms":None,"analysis_ms":None,"queue_wait_ms":None}}
    (folder/"validation_report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
