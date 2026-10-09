# SecureSight remediation and validation — 8 October 2026

Known audit defects have been repaired and the local application is running for testing. **Public launch is not yet approved by the available evidence.** This report supersedes historical completion statements and model metrics in the earlier phase documents; the original audit is retained as a historical snapshot.

## Corrected model and evaluation

Active trusted bundle: models/v5. Model and feature-schema version: **5.1.1**. Python 3.12.10; scikit-learn 1.5.1. Actual estimators: LR, random forest and ExtraTrees in grouped OOF stacking, with separate sigmoid calibration.

PhiUSIIL source labels are inverted explicitly: publisher 1 legitimate / 0 phishing -> project 0 legitimate / 1 phishing. Source CSV was not changed. Its SHA256 is a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6.

Corrected dataset: **234,885 rows**, 134,849 legitimate and 100,036 phishing. Full URL path/query/fragment is preserved; normalized URL conflicts use majority vote, phishing only on a documented tie. Private suffixes and unknown suffix hosts retain appropriate domain grouping.

The contract contains **97 fields: 59 URL, 9 domain, 22 HTML, 7 content**. Only the 59 observed URL fields are learned. The source does not contain representative labeled raw domain/HTML snapshots. Those optional fields remain missing in training and are separate observed decision evidence at runtime; they are not fabricated classifier contributions.

| Frozen partition | Rows | Domains |
| --- | ---: | ---: |
| Train | 165,436 | 137,231 |
| Calibration | 16,858 | 14,703 |
| Threshold selection | 17,037 | 14,704 |
| Final test | 35,554 | 29,407 |

All four domain sets are disjoint. Training preprocessing is fitted within folds. Threshold selection is separate from calibration/test; selected threshold **0.93**, objective maximizing recall subject to observed selection FPR <=1%. Grouped fold audits and row IDs are recorded. No final test threshold tuning was performed.

| URL-classifier historical test metric | Result |
| --- | ---: |
| Accuracy | 98.529% |
| Precision | 99.395% |
| Phishing recall | 97.192% |
| F1 | 98.281% |
| ROC AUC | 0.992876 |
| PR AUC | 0.994122 |
| False-positive rate | 0.4511% |
| False-negative rate | 2.8083% |
| ECE | 0.006913 |
| TN / FP / FN / TP | 20,080 / 91 / 432 / 14,951 |

These metrics measure the **URL classifier**, not the full decision policy or a live public-web safety guarantee. Earlier versions used the same historical source; a genuinely fresh temporal/domain holdout remains required.

An initial corrected-label experiment reached 99.51% historical accuracy but independent development checks exposed a severe www shortcut: plain legitimate domains were scored very differently from their www variants. That experiment is retained under data/v5_1 and reports/remediation_20261008/training, and is not the serving bundle. Version 5.1.1 normalizes conventional www prefixes only in the lexical view. Network destinations are unchanged. Paired www/plain checks now agree for benign and suspicious examples; Google/GitHub/Microsoft/Wikipedia/Amazon legitimate examples pass regression checks. No allowlist was added to force these results.

## Audit findings addressed

| Finding | Remediation and practical scope |
| --- | --- |
| C1 — reversed labels and contaminated blacklist | Explicit source conversion, fresh versioned data/features/model, corrected compatibility cleaned.csv. Historical list rebuilt from training-only exact hosts, excludes mixed-label hosts, and checks CSV provenance/hash. Matches are unconfirmed SUSPICIOUS; non-hits UNKNOWN. |
| C2 — DNS preflight disconnected from sockets | Shared pinned literal-IP gateway for GET, TLS, HEAD and WHOIS. Host/SNI/certificate identity retained; mixed/private answers blocked; each redirect revalidated. Tests assert no private connection construction. |
| H1 — main scan ignored Phase 5 | Main HTML/API/legacy scan uses corrected predictor and shared P2/domain/static-web evidence pipeline. |
| H2 — mismatched/zero-filled features | Shared extractor/order, strict 97-field contract, required actual URL fields, null/NaN optional observations. Only 59 observed fields are claimed as learned; joint domain/HTML ML requires a new corpus. |
| H3 — failed analysis became legitimate | Failed essential stages return Analysis incomplete. Inference failure has null prediction/probability. Phase 6 now applies centralized coverage, confidence, independent-source and contradiction gates; see docs/VERDICT_POLICY.md. Unavailable image/email models cannot produce definitive safety/authenticity claims. |
| H4 — broken/leaky CV | Corrected entry point, actual estimator constructors, fold-local pipelines, grouped OOF and tuning, independent calibration/threshold domains. Prior direct training path retired. |
| H5 — irreproducible metrics | Source/processed/split/artifact hashes, frozen IDs, environment/model/schema/threshold records, saved probabilities. Metrics reproduced directly from saved final predictions without another model evaluation. |
| H6 — fake SAFE reputation | Unimplemented keyed providers UNAVAILABLE; non-hits UNKNOWN; partial/failed providers cannot establish aggregate SAFE. Historical matches are not a current threat feed. |
| H7 — unbounded work | Bounded dnspython queries without global socket settings; retrieval deadlines/caps; DOM budgets; bounded copied cache; every heavy API/form shares capacity. Infrastructure worker/egress controls still required. |
| H8 — missed resources/forms | urljoin/base resolution covers protocol-relative/relative URLs; all credential forms checked; cross-domain login alone is not definitive phishing. |
| M1 — absent parser dependency | BeautifulSoup is installed and pinned in runtime requirements; clean dependency/import checks pass. |
| M2 — raw error disclosure | Safe statuses/messages and content-free logs. Test secrets do not appear in public errors/logs. Optional diagnostic failures are logged without raw exception text. |
| M3 — cache collisions/growth | Scheme/host/port keys, monotonic TTL, bounded 512-entry LRU, copied payloads, expiry sweep. |
| M4 — unsafe response handling | Successful HTTP/HTML type required, identity encoding, byte/content-length/deadline checks, unconditional response/pool cleanup. |
| M5 — fabricated dynamic analysis | Explicit NOT_EXECUTED / SKIPPED / DYNAMIC_ANALYSIS_UNAVAILABLE. No browser/sandbox enforcement is falsely claimed. Actual isolated browser analysis remains a separate implementation. |
| M6 — weak/broken tests | Source label, corrupt/missing model, www invariance, private redirect/socket identity, all forms, DOM caps, missingness, split/fold disjointness, API schema/capacity and integrated verdict regressions added. Obsolete transport mocks/version assumptions repaired. Offline DNS/socket prohibition retained. |
| M7 — serialization mismatch | New trusted bundle trained/validated under pinned runtime. Version/schema/checksum mismatches fail closed. Legacy URL artifact is not used. |
| L1 — misleading documentation | Current architecture/API/security/development/schema/training/reputation/label docs corrected; old reports explicitly marked historical/superseded. |
| L2 — fabricated explanations | Serving explanations are actual probability sensitivity to training medians, explicitly not causal/SHAP. UI identifies URL-only probability and separate heuristic evidence score. |
| L3 — dependency/test cleanup | Proper venv dependencies, pinned test/audit tools, explicit pytest paths/exclusions, vendor audit folders and staging/backups excluded from collection/deployment. Historical evidence retained. |

## Verification evidence

- **219 tests passed**, no test failures. 26 existing SciPy/LogisticRegression deprecation warnings remain; they do not change current results but need review before dependency upgrades.
- Aggregate Python statement coverage **70.43%**. Outbound gateway 88.51%, safe fetch 85.71%, inference 86.72%, scan service 86.09%. Offline training and legacy/optional helpers contribute to uncovered code. This is not a claim of comprehensive production coverage.
- Flake8 fatal/syntax/undefined-name checks: no findings.
- Bandit: **zero high or medium findings; two low findings** for subprocess import/use in the offline pipeline runner. The runner passes fixed repository script paths and the interpreter as an argument list without shell execution. These are reviewed nonblocking observations, not a claim of zero static findings.
- pip check: no broken requirements. Installed-environment pip-audit: **zero known vulnerabilities**. Optional image-ML/container OS packages remain outside this installed-core audit.
- Actual localhost homepage, health and readiness return 200. Private URL API input returns 400. Live Google/GitHub scans return successful DNS/static analysis and No strong phishing indicators with reputation limitations visible. HTML URL form renders. These are smoke checks, not a labeled external accuracy benchmark.
- Docker CLI exists but Docker Desktop Linux daemon is unavailable. No container build, production Redis/TLS/proxy/load test or public deployment was performed.

Evidence files:

- reports/remediation_20261008/tests_final.log and coverage.json
- reports/remediation_20261008/lint_final.log, bandit_final.json, dependency_audit.json
- reports/remediation_20261008/training_v5_1_1/evaluation_report.json, fold_audit.json, threshold_analysis.json, final_test_predictions.npz
- reports/remediation_20261008/live_smoke.json and verify_live.py
- data/v5_1_1/manifest.json and splits.json
- models/v5/model_metadata.json, feature_schema.json, threshold.json and metrics.json

## Public-release gates still open

1. Fresh independently labeled temporal/domain holdout and representative legitimate/phishing examples, with agreed error-rate criteria and false-negative/false-positive review.
2. Representative raw HTML/domain snapshots if joint P2–4 learned classification is required. Current separate evidence scope is disclosed.
3. Real reputation integration/provisioned credentials and any required isolated dynamic browser implementation. Placeholders do not pretend to work.
4. Production Docker build, Redis availability/failure tests, TLS/reverse proxy/egress controls, load/memory/timeout tests, monitoring and rollback verification.
5. Optional email/image classifiers need their own representative validation; image heuristics are not authenticity proof.

The application is available for local testing at http://localhost:5000. No public deployment or 100% accuracy/safety guarantee is made.
