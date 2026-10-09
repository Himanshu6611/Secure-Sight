# Risk scoring 6.0.0

app/risk/engine.py is the single active URL assessment engine. It consumes actual outputs of URL, domain, static web and ML analysis. It does not resolve DNS, fetch pages/resources, parse HTML, train or deserialize models.

The previous inline max(probability, evidence floor) verdict policy in app/services/scans.py has been removed. Phase 2 indicator scores remain contextual diagnostics; legacy reputation helper scores are not used for final URL decisions.

## Configuration

Trusted fixed JSON: config/risk_scoring.json. No new dependency is needed. Parsing rejects duplicate keys, unknown schema fields, invalid/nonfinite numbers and invalid threshold ordering. Category/group weights must be positive and sum to one. Risk/assessment/config versions are 6.0.0; responses also identify the SHA256 of canonical semantic configuration. Change the version when weights or thresholds change.

| Category | Weight |
| --- | ---: |
| URL | 0.15 |
| Domain/DNS/TLS | 0.15 |
| Reputation | 0.20 |
| HTML/DOM/forms/scripts | 0.15 |
| Content/NLP | 0.10 |
| Brand | 0.10 |
| ML | 0.15 |

These are provisional starting policy weights, not fitted probabilities. They allocate more weight to provider evidence than weak wording/brand cues. Actual provider availability and reliability are checked before use. No full-intelligence representative corpus is currently available to optimize them empirically.

## Formula and missingness

Signals first normalize to 0–1. Select only the highest-risk observation in each correlation group, with quality then signal ID as deterministic tie-breakers. Category score is 100 times the weighted mean of observed group values. Missing groups are omitted from that mean, not replaced with benign zero.

Global base risk is the weighted mean of available category scores, renormalized over available category weights. If no category is available, risk is null and verdict ANALYSIS_FAILED. Risk describes observed evidence: on an incomplete input a single category may dominate the observed score, but coverage/confidence and independent-source gates prevent it from controlling a definitive verdict.

Per-signal contribution equals category effective global weight times group effective category weight times normalized value times 100. Selected contributions sum exactly to audit.base_risk_score. Other correlated signals are retained with selected=false and contribution=0.

Explicit provisional floors:

- Cross-domain credential submission plus brand mismatch: risk at least 60, still subject to verdict gates.
- That corroborated webpage finding plus validated calibrated URL probability >=0.85: risk at least 80.
- That finding plus reliable current MALICIOUS provider evidence: risk at least 85.

These rules combine distinct corroborating observations; ordinary password forms, cross-domain SSO, urgency, young domains and IDNs alone cannot trigger them. Floors are policy escalation thresholds, not estimates of event probability. A contradiction still prevents PHISHING.

Severity thresholds: 0 VERY_LOW, 20 LOW, 40 MEDIUM, 60 HIGH, 80 CRITICAL. The displayed rounded score determines its band. Final score safety boundary is 0–100; malformed inputs are rejected before arithmetic, not hidden by clamping.

## Availability and reconstruction

Category evidence coverage is category-weighted observed group fraction; NOT_APPLICABLE groups are excluded from the group denominator. Analysis completeness is the fraction of eight applicable intended inputs fully available: URL, DNS, TLS, registration age, reputation, static HTML, content and ML. Partially observed content contributes its available signals but is not counted as a fully completed stage.

Unsupported dynamic/resource execution is excluded from the intended static baseline and disclosed in warnings. Coverage of this baseline is not a claim that every conceivable security check ran.

The assessment audit contains group selections/weights, exact base contributions, floors, stages, confidence terms, thresholds and configuration identity. Sensitive raw URLs, form destinations, titles and text are not copied into the assessment/audit. Deterministic timing measurements live outside the assessment.

See [signal formulas](SIGNAL_MODEL.md), [confidence](CONFIDENCE_ENGINE.md), [verdict policy](VERDICT_POLICY.md) and [validation limits](RISK_CALIBRATION.md).
