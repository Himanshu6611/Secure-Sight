# Explicit batch correlation

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Only one explicitly submitted batch of at most three messages is compared. Shared sender domains, normalized subject hashes, attachment hashes, perceptual hashes and QR-payload hashes yield bounded groups with hashed identifiers.

No cross-user lookup, global email database or unrelated mailbox mining occurs. Campaign similarity contributes zero independent risk points. Batch risk is the strongest actual message assessment. Similarity does not establish malicious intent.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
