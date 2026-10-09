# Resource limit verification

2026-10-09, local Windows: baseline 757 passed; targeted 39 passed; final 796 passed, 0 failures/errors, 0 skips, 26 warnings. No retries or expected-failure suppression. Evidence: `reports/phase15_20261009/`.

Existing Windows Job CPU/memory, wall timeout, worker-output, worker-start cleanup, environment secret exclusion, decoder-pixel/file-size, bounded static response/crawl/redirect, scan semaphore, actor quota, email queue saturation/expiry/store-failure and provider circuit regressions passed with zero skips. Fake Redis/fixtures are not live Redis saturation. New MIME preflight prevents recursive tree construction for extreme nested MIME. Mutations are serial and bounded; no uncontrolled concurrent workload.

Initial health was the passing baseline, not a measured CPU/RSS production baseline. Final full suite took approximately 68 seconds with branch coverage. No Phase 15 throughput/p95/p99/RSS/saturation measurement; Phase 14 serial dashboard measurements are historical and not reused as Phase 15 load results. No real browser engine is enabled: static analysis limits are tested, abusive-script execution/popups/downloads and browser crash cancellation are UNAVAILABLE. Proven filesystem/network OS isolation remains UNAVAILABLE; production load and alert/cancellation behavior require a dedicated staging job.
