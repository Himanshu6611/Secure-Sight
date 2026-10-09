"""Controlled serial in-memory dashboard benchmark; no network/production data."""
import json
from pathlib import Path
import time
import tracemalloc
import numpy as np
from app import create_app
from app.dashboard.service import capture
from tests.risk.test_engine import context


def main():
    app = create_app({"TESTING": True, "APP_ENV": "testing", "RATELIMIT_ENABLED": False,
                      "DASHBOARD_DB_PATH": ":memory:"})
    app.logger.disabled = True  # This isolated serial benchmark excludes logging I/O.
    store = app.extensions["dashboard_store"]
    store.provision("benchmark-local", "synthetic-fixture-password", "ANALYST", "benchmark")
    account = store.login("benchmark-local", "synthetic-fixture-password")
    record = {"url": "https://example.com/", "status": "ANALYZED", "assessment": app.extensions["risk_engine"].calculate(context())}
    tracemalloc.start(); started = time.monotonic()
    with app.app_context():
        for i in range(500):
            record["url"] = f"https://example.com/fixture/{i}"
            capture(record, "URL", account)
    populate_seconds = time.monotonic() - started
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(dashboard_user=account["id"], dashboard_expires=time.time() + 3600)
    latencies, codes = [], []
    started = time.monotonic()
    for _ in range(200):
        tick = time.perf_counter()
        response = client.get("/api/v1/investigations?limit=25")
        codes.append(response.status_code)
        latencies.append((time.perf_counter() - tick) * 1000)
        if response.status_code != 200 or len(response.json["items"]) != 25:
            raise RuntimeError("Dashboard benchmark response failed")
    duration = time.monotonic() - started
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    output = {"scope": "serial Flask test client, encrypted in-memory SQLite, synthetic 500 records, rate limits explicitly disabled for measurement only",
              "samples": len(latencies), "status_200": codes.count(200), "failure_rate": sum(c != 200 for c in codes) / len(codes),
              "population_seconds": populate_seconds, "p50_ms": float(np.quantile(latencies, .5)),
              "p95_ms": float(np.quantile(latencies, .95)), "p99_ms": float(np.quantile(latencies, .99)),
              "throughput_serial_requests_per_second": len(codes) / duration, "python_tracemalloc_peak_bytes": peak,
              "outbound_calls": 0, "queue_delay": None, "provider_unavailable_rate": None,
              "scan_completion_rate": None, "scan_latency": None,
              "limits": "No concurrency, HTTP transport, decoder/provider work, production Redis, native/RSS peak or saturation measurement"}
    report = Path(__file__).resolve().parents[1] / "reports/phase14_20261009/performance.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(output, indent=2), encoding="utf8")
    print(json.dumps({k: output[k] for k in ("samples", "failure_rate", "p95_ms", "p99_ms")}), flush=True)


if __name__ == "__main__": main()
