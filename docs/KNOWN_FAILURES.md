# Known failures and unavailable evidence

Engineering status: PASS; public release: BLOCKED.

- container_critical_high_findings: FAIL; 11 <= 0
- prospective_external_holdout: UNAVAILABLE; Missing independent evidence; release remains blocked
- campaign_temporal_leakage_evidence: UNAVAILABLE; Missing independent evidence; release remains blocked
- production_worker_isolation: UNAVAILABLE; Missing independent evidence; release remains blocked
- production_load: UNAVAILABLE; Missing independent evidence; release remains blocked
- historical_paypal_redirect_regression: UNAVAILABLE; Missing independent evidence; release remains blocked
- operator_retention_policy_and_restore: UNAVAILABLE; Missing independent evidence; release remains blocked
- production_redis_tls_egress_secrets: UNAVAILABLE; Missing independent evidence; release remains blocked

LOCAL-ML-001 has model-maintainer ownership/review 2026-11-09 as above. Phase 14 fixes future-history inclusion and preserves all known shortcomings. OS worker isolation still lacks a proven filesystem/network sandbox; Windows job limits alone are insufficient. Campaign/time/page-image clone leakage unavailable. Remote CI runner/assets not provisioned or executed. Manual assistive-technology review, genuine manipulated-media accuracy and production concurrent load remain unverified despite passing automated browser E2E. No unavailable result is counted as PASS; no exceptions or blanket retries. Proposed follow-up owners: data-maintainer (prospective/campaign evidence), security-maintainer (sandbox), frontend-maintainer (UI/a11y), operations-maintainer (load/CI). These are role assignments for follow-up, not evidence of completed external work.
