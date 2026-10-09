# SecureSight Phase 6 implementation and verification report

> Historical version 6.0.0 verification. Phase 8 adds a versioned 6.1.0 behavior policy; see PHASE_08_REPORT.md. The representative accuracy-validation gap remains unresolved.

Date: 2026-10-08. Assessment/configuration version: **6.0.0**.

**Status: implementation and integration verified; representative full-intelligence validation pending. Phase 6 is not declared fully complete or production certified.**

## Scope and implementation

Reviewed the Phase 6 requirements, actual Phase 2 URL features/indicators, Phase 3 domain/provider schemas, Phase 4 static HTML/content observations, Phase 5 inference provenance, historical verification report and subsequent remediation report. Integrated a pure deterministic `RiskScoringEngine.calculate(context)` into the existing scan service. It performs no network requests, training or model deserialization.

New modules in app/risk cover schemas, normalization, strict configuration validation, signal collection, correlation-aware aggregation, confidence, verdict policy and the engine. config/risk_scoring.json supplies versioned policy. Configuration SHA256: a11d493fd4cbc56915f3409193c97a09c63bc28f1a8ab6cf4838dbfbb3f5e195.

Seven categories use provisional weights: URL 15%, domain 15%, reputation 20%, HTML 15%, content 10%, brand 10%, ML 15%. Nineteen signals use explicit bounded normalizations. A strongest-signal rule within correlation groups prevents duplicate evidence inflation. Missing values remain missing; available category weights are renormalized and evidence coverage records the loss. Credential harvesting floors of 60/80/85 require specified corroboration. See SIGNAL_MODEL.md and RISK_SCORING.md for exact formulas and provenance.

Confidence combines coverage, quality, source agreement and confirmed calibrated-model decisiveness; contradictions reduce it and coverage caps it. It is a **provisional index, not calibrated correctness probability**. Strong verdicts require confidence, coverage and independent evidence. Failed or insufficient essential observations cannot produce a safety verdict. Static-only analysis and missing external resources/providers are disclosed.

Existing API responses preserve compatibility and add a canonical assessment with configuration hash, category availability, top evidence, missing signals, contradictions and audit. Application startup validates configuration, readiness checks engine availability, and logs restrict assessment fields to safe summaries. ML results expose existing validation/calibration provenance. The minimal page displays Phase 6 metrics; Phase 7 UI work is not implemented. No dependencies were added, models retrained, final-test thresholds tuned, or public deployment performed.

## Verification

| Check | Result |
| --- | --- |
| Full automated suite | 301 passed, 26 warnings; 82 new risk tests |
| Risk statement coverage | 90% (428 statements, 42 missed) |
| Confidence and verdict coverage | 100% |
| Fatal lint checks | Passed |
| Bandit on app/risk | No findings |
| Local page, health, readiness | HTTP 200 |
| Existing scan API integration | Canonical 6.0.0 assessment returned |
| Private-address / unexpected-field rejection | HTTP 400 |

Tests cover score/severity boundaries, all five verdicts, malformed/nonfinite values, model provenance, missing observations, TLS/DNS failures, HTTP applicability, contradictory providers/model/web, duplicate forms/indicators, independent-source gates, deterministic replay, configuration rejection, contribution accounting, privacy and API failure behavior. Logs and coverage are under reports/remediation_20261008/phase6_*; live summaries are in reports/phase6_20261008/live_smoke.json.

The live GitHub scan returned LEGITIMATE. The live Google scan returned SUSPICIOUS because the existing reputation source reported SUSPICIOUS; no independent malicious source or model/web contradiction was present. This is an observed false-alert concern requiring reputation-data validation, not evidence of production accuracy. No site-specific whitelist was inserted to conceal it.

## Development evaluation and limits

scripts/validate_risk.py evaluated **17,037 frozen development rows**, using actual URL/model observations only. Saved HTML/domain snapshots are unavailable. All rows returned UNKNOWN: **0% definitive verdict coverage**. Accuracy, precision, recall, F1, FPR/FNR and confidence-bucket correctness are null, not perfect scores. No missing observations were fabricated, and the final holdout was not used. One row had an unsupported negative feature sentinel, so serving validation withheld model evidence for it.

Observed scoring median/p95: **0.321400 / 0.380700 ms**. Confidence helper: **0.008300 / 0.013200 ms**. JSON serialization: **0.105200 / 0.143085 ms**. These are local measured operations excluding network, not a production SLA. Risk ranged 0–64.1281 and confidence 15–30 in this partial-observation evaluation. See reports/phase6_20261008/validation_report.json for distributions and frozen-data hashes.

## Remaining work before claiming completion

Obtain representative independently labeled snapshots with URL, DNS/TLS/registration/reputation and static HTML/content observations. Audit historical reputation records and their freshness, including benign-domain matches. Freeze domain/time-separated validation and final holdouts; measure false alerts, misses, abstention rates, evidence coverage and confidence-bucket correctness. Tune only validation data, version any changed policy, and evaluate the final holdout after freezing it. Current coefficients and confidence remain provisional. Dynamic behavior and external-provider execution are outside the current implementation.

Required companion documents: RISK_SCORING.md, SIGNAL_MODEL.md, CONFIDENCE_ENGINE.md, VERDICT_POLICY.md and RISK_CALIBRATION.md. The next step is this missing Phase 6 validation before making a public accuracy guarantee or claiming full completion.
