"""Bounded same-fixture dashboard/query benchmark; no providers or private data."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import cProfile
import json
from pathlib import Path
import platform
import pstats
import sqlite3
import subprocess
import time
import tracemalloc
import numpy as np
from app import create_app
from app.dashboard.service import capture, analytics
from tests.risk.test_engine import context

ROOT = Path(__file__).resolve().parents[1]


def distribution(values, elapsed):
    return {"samples": len(values), "p50_ms": float(np.quantile(values, .5)), "p95_ms": float(np.quantile(values, .95)), "p99_ms": float(np.quantile(values, .99)), "throughput_per_second": len(values) / elapsed}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", choices=["before", "after"], required=True)
    args = parser.parse_args()
    app = create_app({"TESTING": True, "APP_ENV": "testing", "RATELIMIT_ENABLED": False, "DASHBOARD_DB_PATH": ":memory:"})
    app.logger.disabled = True
    store = app.extensions["dashboard_store"]
    account = {"id": "benchmark-actor", "tenant": "benchmark", "role": "ANALYST"}
    record = {"url": "https://example.com/", "status": "ANALYZED", "assessment": app.extensions["risk_engine"].calculate(context())}
    with app.app_context():
        for i in range(2000):
            record["url"] = f"https://example.com/fixture/{i}"
            capture(record, "URL", account)
    filters = {"verdict": "LEGITIMATE"}
    trace = []
    store.db.set_trace_callback(trace.append)
    expected = store.listing(account, {}, limit=25)
    store.db.set_trace_callback(None)
    queries = [q for q in trace if q.lstrip().startswith("SELECT")]
    plans = [[r[3] for r in store.db.execute("EXPLAIN QUERY PLAN " + q)] for q in queries]
    work = [0]
    def count_steps():
        work[0] += 100
        return 0
    store.db.set_progress_handler(count_steps, 100)
    store.listing(account, {}, limit=25)
    store.db.set_progress_handler(None, 0)
    tracemalloc.start()
    results = {}
    for name, query_filters, offset in [("listing", {}, 0), ("filtered_listing", filters, 0), ("late_page", {}, 1975)]:
        runs = []
        for _ in range(3):
            latencies = []; tick = time.perf_counter()
            for _ in range(300):
                begin = time.perf_counter()
                result = store.listing(account, query_filters, limit=25, offset=offset)
                latencies.append((time.perf_counter() - begin) * 1000)
                if result["total"] != 2000 or len(result["items"]) != 25:
                    raise RuntimeError("Benchmark correctness failed")
            runs.append(distribution(latencies, time.perf_counter() - tick))
        results[name] = runs
    concurrent = []
    tick = time.perf_counter()
    def request(_):
        begin = time.perf_counter()
        result = store.listing(account, {}, limit=25)
        if result["total"] != 2000: raise RuntimeError("Concurrent count mismatch")
        return (time.perf_counter() - begin) * 1000
    with ThreadPoolExecutor(max_workers=4) as executor:
        concurrent = list(executor.map(request, range(200)))
    results["concurrency_4"] = distribution(concurrent, time.perf_counter() - tick)
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    profile = cProfile.Profile(); profile.enable()
    for _ in range(100): store.listing(account, {}, limit=25)
    profile.disable()
    entries = sorted(pstats.Stats(profile).stats.items(), key=lambda item: item[1][3], reverse=True)[:12]
    analytics_runs = {"cold_ms": [], "warm_ms": []}
    with app.app_context():
        for _ in range(3):
            store.analytics_cache.clear()
            tick = time.perf_counter(); cold = analytics(store, account)
            analytics_runs["cold_ms"].append((time.perf_counter() - tick) * 1000)
            tick = time.perf_counter(); warm = analytics(store, account)
            analytics_runs["warm_ms"].append((time.perf_counter() - tick) * 1000)
            if cold["total_scans"] != warm["total_scans"]: raise RuntimeError("Cache count mismatch")
    output = {"label": args.label, "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "hardware": platform.machine(), "logical_cpu_count": __import__("os").cpu_count(),
              "scope": "2000 generated encrypted rows, in-memory SQLite, direct store listing; three warm repeats each 300 calls; serial plus bounded 4-thread/200-call contention; no network/private data",
              "rate_limits": "Disabled only in isolated app; this measures database/service, not production HTTP admission",
              "cold_start": "Not measured; imports/model loading/population excluded", "results": results, "analytics": analytics_runs,
              "query_plans": plans, "query_count": len(queries), "sqlite_vm_steps_approx": work[0], "python_peak_bytes": peak,
              "profile_top": [{"file": Path(k[0]).name, "line": k[1], "function": k[2], "calls": v[1], "cumulative_seconds": v[3]} for k, v in entries],
              "queue_wait": None, "end_to_end_scan_latency": None, "native_rss_peak": None,
              "snapshot": {"total": expected["total"], "subjects": [v["subject"] for v in expected["items"]]},
              "limits": "No live providers/Redis, HTTP transport, queue, OCR throughput, cold OS cache, production filesystem or field Web Vitals"}
    path = ROOT / f"reports/phase17_20261009/{args.label}.json"
    path.write_text(json.dumps(output, indent=2), encoding="utf8")
    print(json.dumps({"label": args.label, "listing_p95_ms": [r["p95_ms"] for r in results["listing"]], "vm_steps": work[0], "plans": plans}), flush=True)


if __name__ == "__main__":
    main()
