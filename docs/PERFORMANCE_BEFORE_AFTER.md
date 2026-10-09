# Before/after measured performance

2026-10-09 Windows: baseline 815 passed; targeted prior dashboard/security/quality/adversarial 161 passed; five new regressions passed; final 820 tests, 0 failures/errors, 0 skips, 26 warnings.

Environment: 3.12.10 / SQLite 3.49.1; Windows AMD64, Intel i7-13700HX, 24 logical CPUs (hardware.json records memory). Same benchmark code/fixture shape, 2,000 generated encrypted URL records per independent in-memory store. UUIDs/encryption/timestamps regenerated, so workloads are comparable rather than byte-identical databases. Imports/population/model initialization excluded. No private records or public/provider network. Logging and rate limiting disabled only in isolated measurement app; no serving policy change. No CPU affinity or guaranteed idle desktop.

| Workload | Before p95 median (ms) | After p95 median (ms) | Reduction |
|---|---:|---:|---:|
| listing | 4.758 | 1.420 | 70.15% |
| filtered_listing | 5.183 | 1.520 | 70.68% |
| late_page | 6.002 | 1.576 | 73.75% |

Three repeats of 300 serial calls for each workload per variant (2,700 serial calls plus 200 four-thread calls). Warm process/database; late page offset1975; filter all matching LEGITIMATE. Tracemalloc enabled equally for serial/concurrent timings; database population/profiling/cache runs excluded from latency distributions. Raw p50/p95/p99/throughput and tracemalloc peaks retained.

- before listing: p95 repeats [4.712, 4.758, 5.126] ms; p99 repeats [5.006, 5.002, 5.669] ms.
- before filtered_listing: p95 repeats [5.258, 5.183, 5.017] ms; p99 repeats [5.534, 5.512, 5.163] ms.
- before late_page: p95 repeats [6.002, 5.97, 6.039] ms; p99 repeats [6.188, 6.316, 6.377] ms.
- after listing: p95 repeats [1.42, 1.463, 1.407] ms; p99 repeats [1.541, 1.898, 1.512] ms.
- after filtered_listing: p95 repeats [1.543, 1.52, 1.425] ms; p99 repeats [1.808, 1.629, 1.643] ms.
- after late_page: p95 repeats [1.576, 1.586, 1.575] ms; p99 repeats [1.689, 1.744, 1.92] ms.

Four-thread burst: p50 4.649 → 5.592ms (regressed; one burst, contention/noise plausible but not proven); p95 68.351 → 10.262ms; p99 96.248 → 14.682ms; throughput 230.6 → 696.3 calls/s. Tail estimates have limited sample support; no confidence interval or production speedup claim. Every measured call checks expected total/page size; exceptions stop the run, not fabricated successes.

SQL work ~140,300 → 32,900 VM instructions. Queries 1 → 2, plus read savepoint/release; extra query buys efficient indexed limited row retrieval. After page plan uses inv_scope_page without temp sort. Cache cold/warm timings remain descriptive and noisy; no separate cache optimization claimed. Native RSS, HTTP/serialization, disk/WAL latency, queue wait, full URL/media/email execution, startup, payloads, container/field CWV are UNAVAILABLE. No before/after accuracy trade-off; serving artifacts/threshold/scoring unchanged.

Reproduce: `venv/Scripts/python.exe -m scripts.phase17_benchmark --label after`. `--label before` is an artifact name, not a switch to old SQL: rerunning it on new code will measure new code and overwrite the historical before artifact. Preserve original artifacts; use a separate reviewed prior checkout to reproduce old implementation. No production saturation or fair workload-class scheduling claim.
