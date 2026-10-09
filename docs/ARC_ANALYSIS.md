# ARC chain verification

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

dkimpy validates bounded ARC chains with at most four seals. Seal instance, domain, selector, claimed chain-validation value and timestamp are recorded. Actual cryptographic PASS and tampering FAIL are tested.

Uploaded ARC Authentication-Results remain claims. chain_trusted is false because no trusted intermediary policy is configured. ARC PASS does not override SPF/DMARC uncertainty or malicious destination evidence.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
