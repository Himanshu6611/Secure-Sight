# Offline ML robustness

20 deterministic lexical variations across five descriptive hosts, no network requests. Query/path/fragment content is harmless test text, not labeled current page ground truth. Model 5.1.1 frozen; no retraining, tuning, whitelist or promotion.

Observed label changes: 11/20. Maximum absolute probability change: 0.975269. All five case/trailing-dot variants have identical normalized URLs and unchanged predictions. Changing query/path/fragment changes feature vectors and can cross the threshold; this is a material sensitivity finding P15-002, not proof of 55% deployed false positives or an evasion success rate.

Raw per-case evidence is `ml_robustness.json`; preserve it as a challenge artifact. New startups, redesigns, rebrands, third-party mail, marketing redirects, absent C2PA and benign AI content require uncertainty and independent evidence; generated fixture expectations do not create contemporary labels. Existing domain-age-only, brand/logo-only, authentication-only and missing-provider safety regressions pass. Historical PayPal redirected case remains open from Phase 14. Confidence/risk/severity/verdict must not be equated with lexical probability.

Image resize/crop/compression and OCR noise robustness lack a representative labeled paired corpus and validated active deepfake model: UNAVAILABLE. No universal robustness claim. Remediation requires independently labeled, domain/campaign/time-separated train/validation/external holdout and calibration review; preserve frozen test rather than optimizing these 20 cases. Role owner model-maintainer, review 2026-11-09, OPEN; release blocked.
