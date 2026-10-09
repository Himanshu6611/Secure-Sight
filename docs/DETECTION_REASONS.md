# Detection reason mapping and ranking

Each canonical reason has reason_id, signal_id, category, severity, title, description, safe scalar evidence, source, evidence_type, confidence, source_reliability and independence_group. `score_contribution` is present only when Phase 6 actually supplies it. All wording comes from config/explanations.json.

The registry maps URL authority/IP/IDN/spelling/keyword/entropy/length observations; domain registration; DNS restrictions; TLS certificate validation; reputation status; external credential forms; static script/iframe patterns; urgency/credential/financial wording; brand mismatch; and URL-model probability. HTML/password counts are additional unscored contextual observations from the analyzed Phase 4 output, not evidence of maliciousness on their own.

Categories support URL, DOMAIN, DNS, TLS, REPUTATION, HTML, DOM, FORM, SCRIPT, CONTENT, NLP, BRAND, REDIRECT, ML, BEHAVIORAL and SYSTEM. Severity uses INFO/LOW/MEDIUM/HIGH/CRITICAL and is separate from final website severity. REDIRECT/BEHAVIORAL are reserved; Phase 8 detection is not implemented here.

Risk reasons require an available, selected Phase 6 signal with normalized value at least its configured evidence minimum. Contributions descend first, then severity, confidence, source-reliability proxy and stable reason ID. One reason per Phase 6 correlation group survives ranking. URL heuristics and the URL model remain correlated under Phase 6's independent-source accounting; the number of reasons must not be interpreted as the number of independent sources.

Available zero-risk observations have negative descriptions only for explicitly mapped registration/DNS/TLS/reputation/form/brand signals. They describe the actual limited observation, not proof of safety. Missing data never becomes a negative reason. Model perturbation directions appear separately in `ml_explanation`.

Reputation reason titles preserve SAFE/SUSPICIOUS/MALICIOUS status; historical SUSPICIOUS matches are not described as confirmed malicious activity. Script obfuscation, long URLs, IDNs, young domains and password fields have contextual, non-alarmist wording. Contributions can sum to the base score rather than the final score when Phase 6 applies a corroboration floor; `score_adjustments` exposes those floors separately.
