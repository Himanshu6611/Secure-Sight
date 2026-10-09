# Authentication trust

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Uploaded Authentication-Results are parsed as claims, always UNTRUSTED_UPLOAD. DKIM and ARC are independently verified against bounded DNS key lookups. Claimed PASS cannot become verified PASS. Valid signatures authenticate signing relationships, not message safety.

DNS: eight queries, six-second total budget, one-second per query, bounded TXT records and validated public query domains. DNSSEC is not verified. SPF receiver context is unavailable. ARC chain cryptographic validity is separate from trust in the sealing operators. See [RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html) and [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.html).

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
