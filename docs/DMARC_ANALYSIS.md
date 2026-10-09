# DMARC policy and alignment

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

DMARC policy lookup uses the From domain and registrable-domain fallback. Duplicate/invalid policy tags are rejected. Strict and relaxed DKIM alignment are evaluated using actual verified signatures. Aligned DKIM PASS plus policy can establish DMARC PASS.

SPF is unavailable for standalone uploads, so lack of aligned DKIM cannot establish DMARC FAIL when SPF could satisfy alignment. Missing policy is NONE; lookup/format errors are explicit. DMARC PASS is not a legitimacy whitelist.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
