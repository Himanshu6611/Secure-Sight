# Controlled performance baseline

serial Flask test client, encrypted in-memory SQLite, synthetic 500 records, rate limits explicitly disabled for measurement only.

- samples: 200
- status_200: 200
- failure_rate: 0.0
- p50_ms: 6.1096500139683485
- p95_ms: 7.3513600567821396
- p99_ms: 10.676628958899435
- throughput_serial_requests_per_second: 136.2397820169538
- python_tracemalloc_peak_bytes: 1159309
- outbound_calls: 0

200 observations support a local percentile estimate, with limited tail precision. No sustained concurrency, HTTP transport, production SQLite/Redis, scan/provider/decoder latency, queue delay, native RSS, saturation or real workload evidence. Scan completion/partial/failure rates and provider unavailability are unmeasured (null), not zero. Rate limiting is explicitly disabled only in the isolated measurement app, not serving configuration. Re-run `python -m quality.benchmark` on a controlled machine; compare scope/environment before timings. Public production load remains BLOCKED.
