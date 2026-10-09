# Body and HTML analysis

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Bounded plain text and visible HTML text produce deterministic contextual flags for urgency, credentials, MFA, payment, bank changes, executives, secrecy, fear and security language. Anchors retain displayed-versus-actual domain relationships. Hidden blocks, forms, scripts and remote images are counted.

Scripts/styles are removed from extracted text and never executed; images/resources are not loaded. A limited private snippet is returned. Email NLP model is MODEL_UNAVAILABLE with null probabilities; no benchmark or calibrated score is claimed. English keyword rules do not provide multilingual semantic coverage.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
