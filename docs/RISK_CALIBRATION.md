# Risk and confidence validation

Risk and confidence coefficients are **provisional**, not learned or calibrated probabilities. Phase 5 historical URL accuracy must not be presented as Phase 6 verdict accuracy.

## Executed evaluation

Run:

    .\venv\Scripts\python.exe scripts/validate_risk.py

The validator uses the frozen threshold_selection development partition only: 17,037 labeled rows. It does not train a model, fetch pages, fabricate domain/HTML data, change thresholds, or score/tune the final test partition. Model probabilities come from the trusted existing model; serving feature validation determines whether a row can provide model evidence.

The available dataset contains actual URL observations but lacks saved full-intelligence snapshots. Every assessment correctly abstains as UNKNOWN. Definitive coverage is 0%; definitive accuracy/precision/recall/F1/FPR/FNR and confidence-bucket correctness are null. Abstentions are not counted as correct classifications.

The observed risk distribution separates many source classes but is not a calibrated security probability. No claims of full-pipeline accuracy, high-confidence correctness or representative public-web performance follow from this evaluation. The report saves class-conditional risk quantiles, confidence quantiles/buckets, saturation fractions and provenance.

Controlled static fixtures verify policy behavior for benign login, malicious-source agreement, model/web contradiction, legitimate federation/context, missing data and corrupted inputs. They are tests of policy, not an independent real-world accuracy benchmark.

## Evidence and timing

- reports/phase6_20261008/validation_report.json
- reports/phase6_20261008/development_assessments.csv
- reports/remediation_20261008/phase6_tests.log and phase6_coverage.json
- reports/remediation_20261008/phase6_bandit.json
- reports/phase6_20261008/live_smoke.json

Timing covers scoring, confidence helper and JSON serialization separately; no network time is included. Use the report's actual median/p95 measurements, not a production SLA.

## Remaining validation

Obtain independently labeled representative legitimate/phishing snapshots with URL, DNS/TLS/registration/reputation and static HTML/content observations. Freeze validation and final holdouts with domain/time separation. Review false positives/negatives, definitive verdict coverage, suspicious/unknown rates, saturation and confidence bucket correctness. Tune only validation; increment configuration version; use final holdout once after freezing policy.

External providers/dynamic browser execution remain unimplemented, and the engine discloses their absence. Production deployment and calibrated confidence are not approved by this Phase 6 partial-observation evaluation.
