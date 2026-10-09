# Performance objectives

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
