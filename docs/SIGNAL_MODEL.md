# Signal model

Each normalized signal contains signal_id, category, group, name, value, normalized_value, weight, severity, source, confidence, reason, state, selected and contribution.

Signal confidence is measurement/source quality in 0–1, not a calibrated correctness probability. It is zero for unavailable/not-applicable signals. State is AVAILABLE, UNAVAILABLE, ERROR, TIMEOUT or NOT_APPLICABLE. Missing normalized values are null. Available zero-contribution reasons explicitly avoid asserting safety; absent-signal reasons do not fabricate observations.

## Normalization

Let clamp01(x)=min(1,max(0,x)); all raw numeric inputs must be finite and valid before applying a documented saturation. Boolean flags accept only booleans or 0/1. Ramp values must be nonnegative.

| Signal | Normalized formula | Group |
| --- | --- | --- |
| IP host | 0.65 × boolean | URL authority |
| Authority @ obfuscation | 0.80 × boolean from the existing Phase 2 indicator | URL authority |
| IDN/Punycode | 0.20 × boolean | URL identity |
| Typosquatting | 0.65 × boolean | URL identity |
| URL lure words | 0.30 × clamp01(count/3) | URL lure |
| URL entropy | 0.30 × clamp01((entropy−4.5)/2.5) | URL complexity |
| URL length | 0.20 × clamp01((length−150)/300) | URL complexity |
| Young registration | 0.60 × (1−clamp01(age_days/90)) | Domain registration |
| Unsafe DNS destination | 1−is_ssrf_safe | Domain DNS |
| Invalid certificate | 0.35 × (1−certificate_valid) | Domain TLS |
| Reputation | SAFE 0, SUSPICIOUS 0.60, MALICIOUS 1 | Reputation provider |
| External credential form | 0.85 × boolean(any external password form) | HTML destination |
| Obfuscated scripts | 0.30 × clamp01(count/3) | HTML scripts |
| External iframes | 0.20 × clamp01(count/3) | HTML embedding |
| Urgency | 0.60 × existing urgency_score | Content urgency |
| Credential wording | 0.35 × existing credential_score | Content credentials |
| Financial wording | 0.15 × existing financial_language_score | Content finance |
| Brand mismatch | Existing mismatch boolean | Brand identity |
| ML | Validated URL phishing probability | ML model |

All maxima/formulas/parameters/qualities/weights are centralized in the JSON configuration. Wording, entropy, IDNs, TLS and age are weak contextual indicators; they do not individually establish phishing.

The lexical view uses existing extraction outputs. A query containing an email @ is not counted as authority obfuscation. The existing min_brand_distance=-1 not-applicable sentinel is recognized as missing, not negative risk; it is not a scoring input. Serving model validation still controls whether its own required vector can be used.

## Correlation and sources

URL authority/identity/lure/complexity groups have weights 0.30/0.30/0.20/0.20. Domain age/DNS/TLS weights are 0.35/0.35/0.30. HTML destination/script/embedding weights are 0.70/0.15/0.15. Content urgency/credentials/finance weights are 0.40/0.40/0.20. Each remaining category has one group.

Within a group, max selection prevents aliases/repeated indicators from accumulating extra score. Form observations collapse to an any-form boolean; repeated forms/indicators do not inflate it. Password count and generic login wording are not stacked as credential harvesting.

Agreement uses only three independent evidence sources: URL_MODEL, REPUTATION and STATIC_WEB. URL heuristics and lexical ML count together. HTML, brand and NLP from one page count together. Registration age and valid TLS/DNS do not prove legitimacy or add independent phishing corroboration.

Reliable SAFE/MALICIOUS status needs matching provider records with confidence >=0.8. Aggregate SAFE with a failed/non-safe provider is ignored. Historical matches remain SUSPICIOUS and cannot supply confirmed malicious corroboration.
