# DKIM verification

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

dkimpy verifies original byte signatures using DNS TXT keys. Up to two signatures, RSA-SHA256 and minimum 2048-bit RSA are supported. Domain, selector, canonicalization, alignment, body-length restriction and signature timestamps are recorded.

Other algorithms produce explicit unsupported/permanent-error status. Verification failure and DNS temporary error remain separate. Real signed RSA fixtures pass, changed bodies fail, and a valid unrelated signer does not establish DMARC alignment. Signature PASS never reduces URL risk.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
