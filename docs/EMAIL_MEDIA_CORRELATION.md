# Media and cross-modal correlation

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

One supported attachment image reuses Phase 10 original hashes, perceptual hashes, bounded forensics, real OCR/multi-QR, offline C2PA, brand findings and full website callback. Graphs connect the email, identities, domains, attachments, media and destination evidence.

Shared URLs are analyzed once even when found in body and QR; strongest evidence is not summed repeatedly. Phase 10 evaluated deepfake/visual-logo models remain unavailable. Missing probabilistic media/email/cross-modal confidence remains null. Graph caps are 512 nodes and 1024 edges.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
