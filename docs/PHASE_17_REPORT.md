# SecureSight Phase 17 report

Status PARTIALLY COMPLETE: measured local database optimization delivered; production/mixed-pipeline and field performance remain unverified. Public release remains BLOCKED by prior findings.

## 1. Architecture confirmed

Flask/Jinja, Python 3.12.10, SQLite encrypted snapshots/WAL, local aggregate cache, bounded email jobs/production Redis, subprocess media and approved URL stack, Docker/non-root multi-stage/Gunicorn.

## 2. Baseline

2026-10-09 Windows: baseline 815 passed; targeted prior dashboard/security/quality/adversarial 161 passed; five new regressions passed; final 820 tests, 0 failures/errors, 0 skips, 26 warnings.

2,000 generated records, three 300-call warm repeats per listing workload, one 200-call four-thread burst, in-memory service-level benchmark. No live targets/private content; environment and raw distributions recorded.

## 3. Bottleneck

Window-count materializes/sorts tenant result before LIMIT. Before EXPLAIN temp B-tree and ~140,300 VM steps substantiate diagnosis. Existing three-repeat p95 4.712–5.126ms for first page.

## 4. Changes

Database/API: separate same-filter count and limited indexed query in consistent read SAVEPOINT; additive order index. Cache: existing behavior retained/tested, no shared private cache. Analysis, frontend, workers, deployment/concurrency untouched. Ancillary validation fix: unused XML SAX escape import in SEO replaced by html.escape, avoiding parser-module import and resolving static warning without changing XML text semantics. Phase 16's initial Bandit warning was not a proven XML parser exploit; current scan has zero findings.

## 5. Files

app/dashboard/store.py (query/snapshot/index); app/seo.py (safe simpler escaping import); scripts/phase17_benchmark.py (controlled profile/before-after); tests/test_phase17_performance.py (five deterministic regressions); scripts/report_phase17.py and six performance reports (actual evidence). Phase 16 static-scan documentation corrected to distinguish its historical warning from current PASS.

## 6. Before/after

| Workload | Before p95 median (ms) | After p95 median (ms) | Reduction |
|---|---:|---:|---:|
| listing | 4.758 | 1.420 | 70.15% |
| filtered_listing | 5.183 | 1.520 | 70.68% |
| late_page | 6.002 | 1.576 | 73.75% |

Four-thread tail improved but p50 worsened 4.649→5.592ms; one burst is limited/noisy. Query count increases 1→2 while work decreases 140,300→32,900. Not an application-wide/public speed guarantee. Detailed repeats/p99/cache/profile/plans/limits in PERFORMANCE_BEFORE_AFTER.

## 7. Validation

PASS: final full suite after escaping fix, 161 targeted prior regressions, five new query/snapshot/cache tests, 24 SEO/performance retest, fatal flake8, scoped strict mypy quality/gates.py, two Node syntax checks, Bandit (0), pip check, pinned dependency audit (0 known advisories), secret inventory and whitespace checks. NOT RUN: Docker image build/startup/size, whole-repo strict typecheck, frontend bundler build (vanilla/no bundler), Lighthouse/field CWV, production provider/queue/disk/concurrency saturation.

## 8. Security/correctness

Same tenant and bound filters, immutable summaries, no-store/noindex unchanged. External WAL writer test proves count/page snapshot; nested rollback test proves listing cannot commit outer writes. Existing cache tenant/copy/invalidation tests pass. Full suite covers SSRF/pinned DNS, parser/upload/resource limits, outages and Phase 6/7 evidence/scoring authority. Model hash/threshold unchanged. No new credential, provider request or telemetry input leak.

## 9. Remaining P0–P3

Prior OS isolation/ML/public-release blockers; staging load and pipeline/queue metrics; index write/startup/storage costs; frontend/field metrics; defer speculative model/infrastructure shortcuts. Operations/backlog documents describe exact scope, rollback and missing evidence.

## 10. Honest status

Local optimization and regression evidence complete. Full performance phase partial because representative deployed HTTP/pipeline/worker/field metrics and saturation evidence are unavailable. No speed, capacity, accuracy or safety guarantee; no deployment or external publication performed.
