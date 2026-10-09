# SecureSight Phase 14 report

Executed 2026-10-09 on Windows; 859 tests, 0 failures/errors, 0 skips. Historical pre-remediation baseline: 731 passed. Evidence: `reports/phase14_20261009/`; commands/logs and JUnit are retained.

Engineering quality gates: PASS. Public-release gate: BLOCKED; nonzero release command is intentional evidence of unmet requirements. Phase 14 is PARTIAL against the entire document's definition of done.

Implemented reproducible staged gates, frozen evaluation/comparisons/calibration/CIs, source identity, controlled benchmark, CI configuration, safe regression fixtures and cross-phase contract/metamorphic tests. Fixed backward-clock future-history leakage without rewriting historical evidence. Existing serving model, probability threshold and datasets remain unchanged.

| Gate | Result | Evidence/detail |
|---|---|---|
| lint_0 | PASS | gate_lint_0.log; 1.891s |
| lint_1 | PASS | gate_lint_1.log; 1.000s |
| type_0 | PASS | gate_type_0.log; 0.406s |
| frontend_0 | PASS | gate_frontend_0.log; 15.890s |
| frontend_1 | PASS | gate_frontend_1.log; 5.313s |
| frontend_2 | PASS | gate_frontend_2.log; 0.594s |
| frontend_3 | PASS | gate_frontend_3.log; 3.281s |
| frontend_4 | PASS | gate_frontend_4.log; 142.297s |
| frontend_5 | PASS | gate_frontend_5.log; 16.422s |
| frontend_6 | PASS | gate_frontend_6.log; 0.062s |
| model_0 | PASS | gate_model_0.log; 15.891s |
| model_1 | PASS | gate_model_1.log; 2.031s |
| tests_0 | PASS | gate_tests_0.log; 75.094s |
| security_0 | PASS | gate_security_0.log; 1.515s |
| security_1 | PASS | gate_security_1.log; 0.704s |
| dependencies_0 | PASS | gate_dependencies_0.log; 0.703s |
| dependencies_1 | PASS | gate_dependencies_1.log; 80.406s |
| performance_0 | PASS | gate_performance_0.log; 9.609s |
| critical_statement_coverage | PASS | 92.2652 >= 80 |
| critical_branch_coverage | PASS | 84.854 >= 60 |
| test_failures | PASS | 0 <= 0 |
| unapproved_skips | PASS | 0 <= 0 |
| historical_fpr | PASS | 0.004511 <= 0.01 |
| historical_fnr | PASS | 0.028083 <= 0.1 |
| historical_ece | PASS | 0.00691292 <= 0.05 |
| leakage_replay | PASS | Frozen grouped partition checks and prediction replay |
| serial_dashboard_p95_ms | PASS | 7.35136 <= 250 |
| serial_dashboard_failure_rate | PASS | 0 <= 0 |
| full_ui_accessibility_e2e | PASS | 7 Playwright tests; 0 failed/flaky, 0 skipped; includes route, scanner, keyboard, contrast and responsive checks |

Historical frozen model FPR 0.4511%, FNR 2.8083%; no public accuracy guarantee. Source/env/model hashes, calibration, per-class metrics, leakage limitations and raw test artifacts retained. Python 3.12.10, sklearn 1.5.1, NumPy 1.26.4, seed 20261009; commit `faac15eed36881216618f9d1fb3544edb8a2ea46` plus dirty-working-tree source_snapshot.json (commit alone does not identify this implementation).

See TEST_INVENTORY, TEST_STRATEGY, DATASET_CARD, ML_EVALUATION, MODEL_COMPARISON, REGRESSION_CORPUS, PERFORMANCE_BASELINE and KNOWN_FAILURES. Local stages including browser E2E executed; remote CI was not executed. Full release blockers remain mandatory and cannot be bypassed by completing phase numbering. No deployment, commit or external publishing performed.
