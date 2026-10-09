"""Generate performance evidence documents from bounded measured artifacts."""
import hashlib
import json
from pathlib import Path
import platform
import statistics
from importlib.metadata import version
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "reports/phase17_20261009"
D = ROOT / "docs"


def read(name):
    return json.loads((R / name).read_text(encoding="utf8"))


def write(name, body):
    (D / name).write_text(body.strip() + "\n", encoding="utf8")


def main():
    before, after = read("before.json"), read("after.json")
    junit = ET.parse(R / "final.xml").getroot()
    cases = list(junit.iter("testcase"))
    errors = len(list(junit.iter("failure"))) + len(list(junit.iter("error")))
    skips = len(list(junit.iter("skipped")))
    bandit, deps = read("bandit.json"), read("dependency_sbom.json")
    table = "| Workload | Before p95 median (ms) | After p95 median (ms) | Reduction |\n|---|---:|---:|---:|\n"
    comparisons = {}
    for name in ("listing", "filtered_listing", "late_page"):
        b = statistics.median(v["p95_ms"] for v in before["results"][name])
        a = statistics.median(v["p95_ms"] for v in after["results"][name])
        comparisons[name] = {"before_p95_ms": b, "after_p95_ms": a, "reduction_percent": 100*(1-a/b)}
        table += f"| {name} | {b:.3f} | {a:.3f} | {100*(1-a/b):.2f}% |\n"
    detail = "\n".join(f"- {label} {name}: p95 repeats {[round(v['p95_ms'],3) for v in data['results'][name]]} ms; p99 repeats {[round(v['p99_ms'],3) for v in data['results'][name]]} ms." for label, data in (("before", before), ("after", after)) for name in ("listing", "filtered_listing", "late_page"))
    summary = f"2026-10-09 Windows: baseline 815 passed; targeted prior dashboard/security/quality/adversarial 161 passed; five new regressions passed; final {len(cases)} tests, {errors} failures/errors, {skips} skips, 26 warnings."
    write("PERFORMANCE_AUDIT.md", """# Phase 17 audit

Confirmed Flask/Jinja server-rendered pages and vanilla JS, Python 3.12, encrypted tenant-indexed SQLite with WAL and one process-local locked connection; existing five-second tenant/filter aggregate cache. Email jobs use local bounded slots and encrypted Redis results in production; URL scans synchronous, media uses resource-limited subprocesses. Shared URL model loads approved artifacts. Phase 6 risk and Phase 7 explanations remain centralized. Docker already multi-stage/non-root; Gunicorn sync workers bounded by configuration.

Representative journeys: public guides/home; authenticated dashboard listing/aggregate/detail/export; bounded URL/domain/website/brand analysis; email parser/auth/links/attachments/job progress; image decode/OCR/QR/C2PA. Source review found existing pagination, duplicate-link reuse, circuit breakers, input/worker/queue bounds. No extra infrastructure, provider concurrency, model compression or private response caching justified by this measurement.

P1 measured bottleneck: Store.listing used count(*) OVER() with optional bound filters and global ORDER BY per tenant. EXPLAIN before shows CO-ROUTINE, scan and USE TEMP B-TREE FOR ORDER BY. Approximately 140,300 SQLite VM instructions for a 25-row first page from 2,000 generated records. cProfile and actual query plans retained. Existing indexes did not support the window materialization/order efficiently. Chosen remedy has high cause confidence and low correctness risk when count/page use a single read snapshot; moderate migration/write storage cost for one extra index.

Cold analytics decrypts telemetry and selected subjects: ~64–66ms before, while existing warm cache ~0.066ms; this is not an N+1 network path. No new aggregate/private cache added. New public guides already use local CSS/system fonts/no JS. No frontend, queue, provider, inference, image compression or worker-count bottleneck was established. Field CWV/production cold start/container size/provider latency/native RSS/saturation unmeasured; don't optimize them by guesswork.
""")
    write("PERFORMANCE_OBJECTIVES.md", """# Performance objectives

Targets are provisional engineering regression objectives, not public SLO promises. No production traffic or hosting measurements available; do not adopt arbitrary millisecond SLAs.

| Journey | Objective/rationale | Method | Role owner |
|---|---|---|---|
| Dashboard first page | Avoid full-result sort/window materialization, keep exact count/pagination | Deterministic EXPLAIN and two-query contract tests; same 2,000-row three-repeat benchmark | backend-maintainer |
| Dashboard concurrent readers | Bounded four-thread test and no count inconsistency | One 200-call burst per variant; no saturation claim | backend/operations-maintainer |
| Aggregate analytics | Preserve five-second cache scope/copy/invalidation; no stale score promotion | Existing/new scoped-cache tests; three cold/warm measurements | backend-maintainer |
| URL/email/media | Preserve bounds, provenance, verdict and explicit partial states | Full regression suite, mocked outages and real local OCR/worker fixtures | analysis-maintainer |
| Production API/queue | Set SLO only after staging load and resource evidence | Dedicated controlled HTTP/mixed-workload/queue job required | operations-maintainer |
| Frontend/CWV | No regression from backend change; measure field/lab separately | Unchanged asset bytes; Lighthouse/field metrics unavailable | frontend-maintainer |

Query-plan/correctness gates are robust to CI scheduling noise; no microsecond assertion or retry masks regressions. Serious timing budgets belong on a dedicated runner after traffic/hosting constraints are known. Existing Phase 14 coarse serial gate remains unchanged and is not a Phase 17 deployed SLA.
""")
    benchmark = "# Before/after measured performance\n\n" + summary + "\n\nEnvironment: " + before["python"] + " / SQLite " + before["sqlite"] + "; Windows AMD64, Intel i7-13700HX, 24 logical CPUs (hardware.json records memory). Same benchmark code/fixture shape, 2,000 generated encrypted URL records per independent in-memory store. UUIDs/encryption/timestamps regenerated, so workloads are comparable rather than byte-identical databases. Imports/population/model initialization excluded. No private records or public/provider network. Logging and rate limiting disabled only in isolated measurement app; no serving policy change. No CPU affinity or guaranteed idle desktop.\n\n" + table
    benchmark += "\nThree repeats of 300 serial calls for each workload per variant (2,700 serial calls plus 200 four-thread calls). Warm process/database; late page offset1975; filter all matching LEGITIMATE. Tracemalloc enabled equally for serial/concurrent timings; database population/profiling/cache runs excluded from latency distributions. Raw p50/p95/p99/throughput and tracemalloc peaks retained.\n\n" + detail
    b, a = before["results"]["concurrency_4"], after["results"]["concurrency_4"]
    benchmark += f"\n\nFour-thread burst: p50 {b['p50_ms']:.3f} → {a['p50_ms']:.3f}ms (regressed; one burst, contention/noise plausible but not proven); p95 {b['p95_ms']:.3f} → {a['p95_ms']:.3f}ms; p99 {b['p99_ms']:.3f} → {a['p99_ms']:.3f}ms; throughput {b['throughput_per_second']:.1f} → {a['throughput_per_second']:.1f} calls/s. Tail estimates have limited sample support; no confidence interval or production speedup claim. Every measured call checks expected total/page size; exceptions stop the run, not fabricated successes.\n"
    benchmark += f"\nSQL work ~{before['sqlite_vm_steps_approx']:,} → {after['sqlite_vm_steps_approx']:,} VM instructions. Queries 1 → 2, plus read savepoint/release; extra query buys efficient indexed limited row retrieval. After page plan uses inv_scope_page without temp sort. Cache cold/warm timings remain descriptive and noisy; no separate cache optimization claimed. Native RSS, HTTP/serialization, disk/WAL latency, queue wait, full URL/media/email execution, startup, payloads, container/field CWV are UNAVAILABLE. No before/after accuracy trade-off; serving artifacts/threshold/scoring unchanged.\n\nReproduce: `venv/Scripts/python.exe -m scripts.phase17_benchmark --label after`. `--label before` is an artifact name, not a switch to old SQL: rerunning it on new code will measure new code and overwrite the historical before artifact. Preserve original artifacts; use a separate reviewed prior checkout to reproduce old implementation. No production saturation or fair workload-class scheduling claim.\n"
    write("PERFORMANCE_BEFORE_AFTER.md", benchmark)
    write("PERFORMANCE_OPERATIONS.md", """# Operations, migration and rollback

No worker count, Redis TTL, provider timeout, upload/parser/decoder limit or scoring rule changed. Existing scan slots, provider circuits, queue slots, input ceilings and fail-closed statuses remain. No HTTP/private-result caching or compression added; private no-store/noindex headers remain. Existing aggregate cache is tenant/filter scoped, copied on return, five-second TTL and cleared on saves/purge; active local job count refreshed. Cross-process cache invalidation still depends on TTL, so multi-worker freshness is a future concern, not fixed here.

Store startup adds CREATE INDEX IF NOT EXISTS inv_scope_page ON investigations(tenant,created_at DESC,id). Existing old index retained for compatibility; no table rewrite, data deletion or evidence migration. On bounded 2,000-row-per-tenant data this is small, but total tenants/database size is unknown. Dedicated staging must measure startup/index write/storage cost and lock contention before production deployment. Startup already performs schema setup; coordinate maintenance and encrypted backups where appropriate. Never export private runtime data into source/artifacts.

Listing uses count and limited select with identical bound WHERE under a deferred SAVEPOINT. It shares a WAL read snapshot, composes with existing outer transactions, and releases on errors without committing an outer write transaction. No BEGIN IMMEDIATE for this read path and no external calls under the lock. Account/tenant checks stay on every request. Deep offset still scans skipped entries; total still counts matching rows. No claim of constant-time pagination.

Rollback: restore prior listing implementation; leave additive index harmlessly in place, or remove inv_scope_page during operator-controlled maintenance after verifying no dependent code. No private records deleted. A restored old function on the new schema may use a different plan, so historical timings cannot be recreated by renaming report labels. Current SQLite planner regression tests run in full CI via existing pytest stage; no new distributed infrastructure/paid service required.

Deployment remains unperformed; Docker unavailable/unbuilt and Gunicorn production limits unchanged. Proven filesystem/network worker sandbox remains a prior HIGH assurance gap; resource jobs are not a sandbox. Configure actual hosting based on measured memory/model footprint before increasing replicas.
""")
    write("PERFORMANCE_BACKLOG.md", """# Outstanding performance backlog

P0: prior worker OS filesystem/network isolation and public-release ML/security gaps; no performance shortcut can accept them. Production stuck-job/crash/client-disconnect cancellation and mixed-workload saturation require a controlled staging environment. No risk acceptance implied.

P1: measure production-like HTTP/API/auth/serialization, disk-backed WAL concurrent readers/writers, actual hosting cold start and loaded model memory; measure URL-provider/crawl, email queue wait and OCR/media execution separately. Verify provider quotas and fair workload admission before worker tuning. Multi-worker aggregate freshness remains bounded by existing TTL but is not immediate invalidation.

P2: deep-offset/keyset pagination if demonstrated by real usage; possible covering/filter indexes only after selectivity/write-cost evidence; analytics telemetry filtering/decryption only if cold cost becomes material. Dedicated frontend Lighthouse/field CWV/accessibility measurements and private dashboard DOM profiling; no frontend speedup assumed from SQL. Measure added index file/write/startup cost before public rollout.

P3: compression, quantization, infrastructure migration, browser-enabled crawling and provider parallelization deferred: absent benefit/quality/isolation evidence. Current benchmark isolates listing; it does not establish whole-application capacity or external-source performance.
""")
    environment = {"python": platform.python_version(), "flask": version("flask"), "sqlite": after["sqlite"], "git_commit": after["git_commit"], "working_tree": "dirty; source hashes recorded", "sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in ("app/dashboard/store.py", "app/seo.py", "scripts/phase17_benchmark.py", "tests/test_phase17_performance.py", "requirements-dev.txt")}, "model_sha256": hashlib.sha256((ROOT / "models/v5/model.pkl").read_bytes()).hexdigest(), "tests": len(cases), "failures": errors, "skips": skips, "bandit_findings": len(bandit["results"]), "known_dependency_vulnerabilities": len(deps.get("vulnerabilities", [])), "comparisons": comparisons, "release": "BLOCKED"}
    (R / "verification.json").write_text(json.dumps(environment, indent=2), encoding="utf8")
    write("PHASE_17_REPORT.md", "# SecureSight Phase 17 report\n\nStatus PARTIALLY COMPLETE: measured local database optimization delivered; production/mixed-pipeline and field performance remain unverified. Public release remains BLOCKED by prior findings.\n\n## 1. Architecture confirmed\n\nFlask/Jinja, Python " + platform.python_version() + ", SQLite encrypted snapshots/WAL, local aggregate cache, bounded email jobs/production Redis, subprocess media and approved URL stack, Docker/non-root multi-stage/Gunicorn.\n\n## 2. Baseline\n\n" + summary + "\n\n2,000 generated records, three 300-call warm repeats per listing workload, one 200-call four-thread burst, in-memory service-level benchmark. No live targets/private content; environment and raw distributions recorded.\n\n## 3. Bottleneck\n\nWindow-count materializes/sorts tenant result before LIMIT. Before EXPLAIN temp B-tree and ~140,300 VM steps substantiate diagnosis. Existing three-repeat p95 4.712–5.126ms for first page.\n\n## 4. Changes\n\nDatabase/API: separate same-filter count and limited indexed query in consistent read SAVEPOINT; additive order index. Cache: existing behavior retained/tested, no shared private cache. Analysis, frontend, workers, deployment/concurrency untouched. Ancillary validation fix: unused XML SAX escape import in SEO replaced by html.escape, avoiding parser-module import and resolving static warning without changing XML text semantics. Phase 16's initial Bandit warning was not a proven XML parser exploit; current scan has zero findings.\n\n## 5. Files\n\napp/dashboard/store.py (query/snapshot/index); app/seo.py (safe simpler escaping import); scripts/phase17_benchmark.py (controlled profile/before-after); tests/test_phase17_performance.py (five deterministic regressions); scripts/report_phase17.py and six performance reports (actual evidence). Phase 16 static-scan documentation corrected to distinguish its historical warning from current PASS.\n\n## 6. Before/after\n\n" + table + "\nFour-thread tail improved but p50 worsened 4.649→5.592ms; one burst is limited/noisy. Query count increases 1→2 while work decreases 140,300→32,900. Not an application-wide/public speed guarantee. Detailed repeats/p99/cache/profile/plans/limits in PERFORMANCE_BEFORE_AFTER.\n\n## 7. Validation\n\nPASS: final full suite after escaping fix, 161 targeted prior regressions, five new query/snapshot/cache tests, 24 SEO/performance retest, fatal flake8, scoped strict mypy quality/gates.py, two Node syntax checks, Bandit (" + str(len(bandit["results"])) + "), pip check, pinned dependency audit (" + str(len(deps.get("vulnerabilities", []))) + " known advisories), secret inventory and whitespace checks. NOT RUN: Docker image build/startup/size, whole-repo strict typecheck, frontend bundler build (vanilla/no bundler), Lighthouse/field CWV, production provider/queue/disk/concurrency saturation.\n\n## 8. Security/correctness\n\nSame tenant and bound filters, immutable summaries, no-store/noindex unchanged. External WAL writer test proves count/page snapshot; nested rollback test proves listing cannot commit outer writes. Existing cache tenant/copy/invalidation tests pass. Full suite covers SSRF/pinned DNS, parser/upload/resource limits, outages and Phase 6/7 evidence/scoring authority. Model hash/threshold unchanged. No new credential, provider request or telemetry input leak.\n\n## 9. Remaining P0–P3\n\nPrior OS isolation/ML/public-release blockers; staging load and pipeline/queue metrics; index write/startup/storage costs; frontend/field metrics; defer speculative model/infrastructure shortcuts. Operations/backlog documents describe exact scope, rollback and missing evidence.\n\n## 10. Honest status\n\nLocal optimization and regression evidence complete. Full performance phase partial because representative deployed HTTP/pipeline/worker/field metrics and saturation evidence are unavailable. No speed, capacity, accuracy or safety guarantee; no deployment or external publication performed.\n")


if __name__ == "__main__":
    main()
