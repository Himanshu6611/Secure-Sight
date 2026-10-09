# Verdict policy 6.0.0

One centralized policy in app/risk/verdict.py determines the canonical verdict. Existing clients also receive a compatible decision label: LEGITIMATE -> No strong phishing indicators; SUSPICIOUS -> Suspicious; PHISHING -> Phishing; UNKNOWN/ANALYSIS_FAILED -> Analysis incomplete.

These names do not establish website safety.

| Verdict | Current requirements |
| --- | --- |
| PHISHING | Risk >=80; confidence >=70; evidence coverage >=65; at least two independent risk sources; safe DNS destination; observed static web; no critical contradiction |
| SUSPICIOUS | Completed essential inputs with risk >=40, a strong source alert, unconfirmed suspicious reputation, or contradiction. On incomplete inputs, at least two risk sources and risk >=40 allow a cautious suspicious result |
| LEGITIMATE | Essential URL/DNS/static-web/validated-model inputs completed; safe DNS; no known invalid/expired TLS; risk <=39; confidence >=65; coverage >=70; no alert/contradiction |
| UNKNOWN | Observations exist but essential inputs or evidence/confidence are insufficient for another verdict |
| ANALYSIS_FAILED | No observable categories or invalid/failed scoring; risk null, never a safe verdict |

All numeric thresholds live in config/risk_scoring.json. Strong calibrated URL probability threshold is 0.85; low probability threshold is 0.15; these are provisional risk-policy inputs, separate from the Phase 5 binary operating threshold 0.93.

An isolated model prediction or one weak feature cannot produce PHISHING. Corroborated webpage evidence can raise a floor, but confidence, coverage, independence and contradiction gates still apply. A low URL probability conflicting with credential/brand observations produces SUSPICIOUS with reduced confidence.

Missing reputation is UNKNOWN, not SAFE. Historical dataset matches remain unconfirmed suspicious observations. Missing optional sources reduce coverage/confidence; they do not become positive safe evidence. HTTP TLS is NOT_APPLICABLE rather than unavailable.

Error codes include MISSING_ANALYSIS_CONTEXT, RISK_INPUT_INVALID, INVALID_SIGNAL, INVALID_SCORE, SCORING_CONFIGURATION_ERROR, VERDICT_CONFIGURATION_ERROR and CONFIDENCE_CALCULATION_ERROR. Invalid deployment configuration fails startup. Scoring/input errors return an explicit ANALYSIS_FAILED assessment with a safe error, null risk and no safety assertion.

The policy is implemented and regression-tested. Empirical validation of definitive verdict accuracy on representative full observations remains pending.
