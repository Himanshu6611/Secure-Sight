# SPF analysis

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Claimed SPF PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR and PERMERROR remain distinguishable. Actual SPF is UNAVAILABLE with TRUSTED_SMTP_PEER_AND_ENVELOPE_UNAVAILABLE.

An uploaded Received line or caller-supplied IP cannot establish the SMTP peer/envelope. The API rejects fake receiver-context fields. A future trusted mail ingress must supply authenticated SMTP context before real SPF can be evaluated. No claimed result causes a safety verdict.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
