# Sender intelligence

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

The From domain reuses Phase 3/9 public domain intelligence through an isolated worker, including available DNS/RDAP/WHOIS/TLS/reputation and separate age fields. Sender display/body claims reuse the existing curated brand registry and confusable normalization.

Public-domain lookup does not authenticate a mailbox. Sender history, ASN attribution and recipient-specific baseline are unavailable. Missing/young domain data or an incomplete brand-registry match is never sufficient for phishing or safety. Existing URL and brand false positives remain possible.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
