# ML evaluation

Executed 2026-10-09 on Windows; 859 tests, 0 failures/errors, 0 skips. Historical pre-remediation baseline: 731 passed. Evidence: `reports/phase14_20261009/`; commands/logs and JUnit are retained.

All 35554 frozen test predictions reproduce to absolute tolerance 1e-12 with identical row order/labels. Serving version 5.1.1; threshold 0.93; schema 5.1.1. No serving fit, promotion or threshold change. Confusion: TN 20080, FP 91, FN 432, TP 14951.

- accuracy: 0.985290
- precision: 0.993950
- recall: 0.971917
- f1: 0.982810
- roc_auc: 0.992876
- pr_auc: 0.994122
- false_positive_rate: 0.004511
- false_negative_rate: 0.028083

Domain bootstrap 95% intervals (200 deterministic replicates): FPR 0.3334–0.5826%; FNR 2.3630–3.3446%. Row Wilson intervals also retained; independence is questionable within domains, so clustered intervals are preferable. These intervals do not quantify source/campaign drift or deployed-system error. Per-class metrics, reliability bins and confusion matrices are in model_comparison.json. ML probability is distinct from risk score, severity, confidence and final verdict.

Raw stack Brier=0.013638, ECE=0.004228; existing sigmoid stack Brier=0.014270, ECE=0.006913. Calibration is measured; sigmoid does not improve every metric, and has not been refitted.

Robustness encoded/IDN/http/query/long-URL slices include small or single-class support; unavailable ROC/PR-AUC and class rates are null. sklearn per-class zero values for unsupported precision/recall are display conventions, not observed performance. Language, page age, compression, provider type and live redirects lack representative labeled paired ML ground truth; integration fixtures do not substitute for those metrics.
