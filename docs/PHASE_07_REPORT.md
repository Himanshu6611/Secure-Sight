# SECURESIGHT PHASE 7 COMPLETE

> Historical explanation version 7.0.0 verification. Phase 8 updates the explanation to 7.1.0 with actual behavioral evidence; see PHASE_08_REPORT.md. Historical measurements below are not Phase 8 measurements.

Date: 2026-10-08. Completion refers to the explanation implementation and its verification, **not** production readiness or guaranteed detection accuracy. Phase 6 representative accuracy validation remains pending.

## Objective and architecture

Implemented deterministic explanations of actual Phase 2–6 observations in the existing URL scan API and server-rendered result page. Inspected the actual URL/domain/static-content/model schemas, historical Phase 1–5 verification report, remediation findings, Phase 6 report/configuration/engine and current local model explanations before implementing this layer. The explanation engine consumes existing evidence and performs no fetching, parsing, DNS lookup, training, model deserialization or LLM call.

## Verification summary

| Area | Result |
| --- | --- |
| Explanation engine | PASS |
| Detection reasons/evidence mapping | PASS |
| Actual local ML sensitivity translation | PASS |
| Evidence ranking/deduplication | PASS |
| Explanation security checks | PASS |
| Existing API and frontend integration | PASS |
| Tests | 351 passed, 0 failed, 26 existing warnings |
| New explanation tests | 50 passed |
| Explanation statement coverage | 90% |
| Fatal lint | PASS |
| Bandit on explanation modules | 0 findings |

## Reason model and ranking

config/explanations.json maps all 19 risk signals and 59 learned URL feature names. Canonical reasons preserve signal ID/source, category/severity, evidence type, confidence, bounded observed scalar value and actual Phase 6 score contribution where supplied. Observations are separated from their registered interpretations. The engine rejects/omits unsupported provenance, invalid normalization and malformed values. Password inputs are contextual observations with no invented risk contribution.

Reasons rank by actual score contribution, severity, confidence, source-quality proxy and stable ID, grouping by existing Phase 6 correlation groups. Five top reasons are configured; fewer appear when fewer findings exist. The summary uses the actual verdict and selected reason titles. Independent source accounting remains Phase 6's responsibility; reason count is not source count. Corroboration floors appear separately from individual contributions.

## Local ML explainability

The serving model's actual training-median perturbation method is retained. Each reported feature includes its actual input value, signed probability impact, direction/magnitude, training baseline and perturbed probability. Tests independently rerun reported substitutions against the trusted model. Missing baselines/failed optional explanation computation return UNAVAILABLE while preserving valid inference. No synthetic SHAP attribution is generated, and no dependency/model/threshold changes are introduced.

Global/offline importance remains separate from local evidence. Legacy global reports without current model provenance are not surfaced as current local explanations. Perturbation effects are not causal or additive and may be affected by correlations or unrealistic median substitutions; these limitations appear in API and UI.

## Risk-reducing observations, conflicts and missing data

Negative descriptions cover only available mapped zero-risk registration, DNS, TLS, provider, form and brand observations. Each describes its limited scope and avoids a safety guarantee. Missing signals never become safe observations. Existing Phase 6 model/provider/web conflict codes are translated without creating new conflicts or findings. UNKNOWN explains insufficient evidence; ANALYSIS_FAILED explains failure; TIMEOUT/failed fetch states appear as unavailable information. Strong verdicts without supporting strong reasons generate an inconsistency warning rather than fabricated reasons.

## Security, privacy and bounds

Trusted JSON registry loading rejects duplicate keys, unsafe templates, unsupported mappings/placeholders and out-of-range limits. Untrusted titles, brand strings, page instructions, URLs, destinations, cookies/tokens and arbitrary raw reason strings are excluded. Only allowlisted scalar evidence is returned. Jinja autoescapes new content; no unsafe HTML insertion or `safe` filter is introduced. Tests cover XSS, JavaScript strings, prompt-injection text, long values, Unicode controls/surrogates, malformed evidence, unsupported ML fields and rendering escape behavior.

Limits bound inputs, reason lists, description length and canonical serialized output (default 49,152 bytes). Technical detail is dropped first when needed, with an explicit warning. No explanation text or sensitive input is added to logs. The canonical limit/privacy guarantee does not re-audit all legacy scan/intelligence compatibility fields.

## Actual measured performance and live checks

500 identical controlled-fixture replays were deterministic. Final measured median/p95:

| Operation | Median ms | p95 ms |
| --- | --- | --- |
| Explanation generation/translation | 0.417150 | 1.286000 |
| Local model perturbation computation | 41.764000 | 64.119000 |
| Explanation JSON serialization | 0.086700 | 0.172900 |

Serialized fixture output: 10,668 bytes. Measurements exclude network and are local observations, not service-level guarantees. reports/phase7_20261008/validation_report.json contains the deterministic replay and safe example.

Latest live /api/v1/scan returned HTTP 200 and version 7.0.0 explanations with available actual local model impacts for GitHub and Google. GitHub returned LEGITIMATE; Google remained SUSPICIOUS from the existing historical reputation alert, and the explanation correctly describes SUSPICIOUS rather than claiming confirmed maliciousness. This remaining dataset-quality concern is recorded rather than hidden with a whitelist. Browser testing verified the reason section and expandable local model details. Evidence: live_smoke.json and browser_result.png under reports/phase7_20261008.

Registry version: 7.0.0. Semantic SHA256: 064bdf778a272887e9fce50f46c6889a05f5f6fd0713be1088345c4220099190. Existing scoring version/hash remain unchanged.

## Files created

- app/explanations/{__init__,engine,reason_registry,validation,ranking,ml_explanation}.py
- config/explanations.json
- tests/explanation/{__init__,test_engine}.py
- scripts/validate_explanations.py
- docs/{EXPLAINABILITY,DETECTION_REASONS,ML_EXPLAINABILITY,EVIDENCE_MODEL,EXPLANATION_SECURITY,PHASE_07_REPORT}.md
- reports/phase7_20261008 validation/live/preview artifacts; reports/remediation_20261008/phase7_* test, coverage, lint and Bandit evidence

## Files modified

app/__init__.py initializes the validated engine; app/services/scans.py integrates canonical explanations while retaining compatibility fields; ml/inference.py exposes actual perturbation baselines/probabilities and safely separates optional explanation failure; app/templates/index.html and app/static/style.css display explanations; README.md and docs/API.md document the result. Pre-existing working-tree changes are preserved.

Dependencies added: **none**. No public deployment, commit, model retraining, final-test tuning, persistent-analysis endpoint, LLM rewriting or Phase 8 behavioral detection was performed.

## Known issues and recommended next step

Explanations faithfully describe evidence but cannot fix inaccurate source labels/providers or establish independently verified accuracy. Current risk weights/confidence remain provisional; representative full-intelligence validation and historical reputation-data review are still required before public readiness. Static evidence cannot describe unexecuted dynamic behavior. Source reliability uses the existing quality proxy, and local perturbations are not causal attribution.

The next implementation phase is **Phase 8 — Redirect & Behavioral Analysis**, subject to its own scope and verification. Do not treat completion of Phase 7 as resolving Phase 6 accuracy validation or as a public safety guarantee.
