# SecureSight API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | /api/v1/scan | Integrated URL/domain/static-web/model analysis |
| POST | /api/analyze | Compatibility alias, same service/quota |
| POST | /api/v1/features/url | 59 URL fields and heuristic indicators |
| POST | /api/v1/intelligence/domain | Domain/DNS/TLS/registration/reputation |
| POST | /api/v1/analyze/webpage | Bounded static HTML/content intelligence |
| POST | /api/v1/ml/predict | Validated model inference |
| GET | /api/v1/health | Liveness |
| GET | /api/v1/ready | Compatible URL model and rate-store readiness |
| GET/POST | / | HTML workbench |

URL feature/domain/web endpoints accept an object containing only url. Integrated scan endpoints additionally accept the optional Phase 9 email_context described below. Example: {"url":"https://example.com/"}.

Scans include url, decision, status, ml_probability, risk_score, risk_score_kind, model_available, ml_result, feature_schema_version, feature_vector, evidence, warnings, timings, explanation, advanced_analysis, domain_intelligence and web_intelligence.

Decisions: Phishing, Suspicious, Analysis incomplete or No strong phishing indicators. Essential failures are incomplete. Model probability applies only to URL classification; risk_score is heuristic evidence priority. Neither guarantees safety. Unknown findings appear in warnings; missing features are null.

Phase 6 adds a canonical `assessment` object to the existing scan response, with `assessment_version`, configuration version/hash, `risk_score`, severity, verdict, confidence, coverage, completeness, signals, contradictions and audit details. Canonical verdicts are LEGITIMATE, SUSPICIOUS, PHISHING, UNKNOWN and ANALYSIS_FAILED. Legacy decision labels remain compatible. `assessment_warnings` contains structured warnings; top-level `warnings` remains a list of string codes. Confidence is a provisional index, not a calibrated probability. No additional public endpoint is introduced.

Phase 7 extends `explanation` with `explanation_version` (7.0.0), registry SHA256, summary, top_reasons, positive_signals, negative_signals, ml_explanation, contradictions, warnings, missing_information, score_adjustments and technical evidence. Existing ml_detail/risk_breakdown remain compatible. ML local features additionally expose actual baseline/perturbed probability and measured sensitivity; these impacts are not additive risk-score contributions. Missing local explanation is explicit and does not erase a valid prediction. No duplicate explanation endpoint or persistent analysis IDs are introduced. See EXPLAINABILITY.md for limits and provenance.

Phase 8 updates assessment/scoring to 6.1.0 and explanation to 7.1.0. Existing scan responses include `behavior_intelligence`, `behavior_feature_version` (8.0.0), and the redacted `analysis_target`; `explanation.behavioral_reasons` and `assessment.behavioral_evidence` preserve actual observations/contributions. The redacted chain distinguishes observed headers from followed targets. Only successfully retrieved final pages provide final URL/lexical/model/domain findings. Private internal routing fields never enter public responses. Scan/web URL paths/query/fragment values and web URL-bearing fields are redacted; remote titles are omitted after analysis. Dynamic browser status is NOT_RUN/NOT_IMPLEMENTED. No new public endpoint or serving model vector is introduced. See PHASE_08_REPORT.md for verification and limitations.

ML accepts features and optionally include_explanations (boolean), explanation_top_k (integer 1–10), and feature_schema_version ("5.1.1"). All 59 URL fields are required; optional fields may be absent/null. Unknown fields, nonnumeric/nonfinite values and invalid vectors are rejected. Empty vectors cannot produce legitimate predictions.

Inference returns status, prediction, probability, threshold, model_version, feature_schema_version, model_scope, unavailable_features and latency_ms. Explanations describe measured sensitivity to training-median perturbation. Failure returns null prediction/probability and safe error codes.

HTTP statuses: 400 invalid input/schema/vector; 403 origin rejection; 404/405 route/method; 413 payload; 415 content type; 429 quota; 503 capacity/model/readiness unavailable; 500 unexpected failure.

Errors have a safe error object and request_id. Responses carry X-Request-ID. APIs are no-store/noindex. Defaults: 8 KiB API payload, 6 MiB forms, 20 scans/minute per direct peer. All heavy API requests/forms share per-worker capacity; training is not public.

Network failures do not expose raw exceptions. Phase-specific endpoints report availability without claiming unavailable evidence is benign.

## Phase 9 additions

Assessment/scoring is 6.2.0 and explanation registry is 7.2.0. Integrated scans add brand_intelligence, brand_feature_version (9.0.0), assessment.brand_evidence and explanation.brand_reasons. The existing ML schema and 97 aggregate fields remain 5.1.1. No new scan endpoint is required.

Optional request example:
```json
{"url":"https://example.com/","email_context":{"sender_domain":"mailer.example","reply_to_domain":"example.com","claimed_brand":"paypal"}}
```

Email context accepts only those three bounded fields; claimed_brand must be a registry ID. Mailbox strings, credentials, arbitrary headers/objects and unsupported fields are rejected with HTTP 400. Sender authentication and full email-link extraction remain unavailable.

Brand status, crawl stops, source/retrieval metadata and separate domain/website/page age fields are explicit. Historical coverage is process-local and PARTIAL, or UNAVAILABLE. First seen is not creation; known brand match is not a safety guarantee. Contextual history/email/similarity evidence is unscored. New private DOM routing data is removed from public scan/web responses. See BRAND_INTELLIGENCE.md and PHASE_09_REPORT.md.
# Phase 10 media endpoint

`POST /api/v1/media/analyze` uses multipart form data, with one `file` part and optional `language`, JSON-string `email_context`, and `source_url` parts. Other APIs retain their 8 KiB JSON limit; media requests have a 6 MiB envelope and 5 MiB file cap. See [media contract](MEDIA_INTELLIGENCE.md) for states, response fields and limits. Failure results never return SAFE. Successful image-only analysis is currently PARTIAL with UNKNOWN authenticity and null model probabilities.

`POST /api/v1/media/investigate` accepts one image in multipart field `image`, optional comma-separated `checks`, and boolean `reverse_search` / `content_safety` flags. It returns the existing media result plus a server-generated `investigation.scan_id`, per-check states and coverage. Reverse search requires explicit opt-in; until an approved provider is configured, even opted-in requests return `not_available` and make no network request. Content safety and AI-origin classification remain `not_available` without validated models. C2PA, metadata, OCR/QR and measured forensic observations reuse the same media pipeline.

## Phase 11 email jobs

`POST /api/v1/email/analyze`: multipart one `.eml` file (message/rfc822, text/plain or application/octet-stream), or a `.pdf`, `.docx` or `.xml` email export (field `file`, max 2 MiB), or JSON `{ "raw_email": "..." }`, or `{ "messages": ["..."] }` for up to three messages. Document exports are passively text-extracted in an isolated worker; they cannot provide trusted transport headers, so sender authentication is unavailable. Existing JSON body limit is 8 KiB; use multipart for larger email. No extra fields or SMTP identity assertions are accepted. HTTP 202 returns job_id, token and poll_url.

Poll `GET /api/v1/email/jobs/<job_id>` with `Authorization: Bearer <token>`. Wrong/missing/expired credentials return 404. Queue/store exhaustion returns 503. States expose parsing/auth/sender/URL/website/media/correlation/scoring and terminal PARTIAL or FAILED. Results do not imply a safety guarantee. See [privacy and retention](EMAIL_PRIVACY.md).
