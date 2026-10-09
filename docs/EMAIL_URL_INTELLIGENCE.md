# Email destination intelligence

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Plaintext, HTML anchors and bounded attachment text discover HTTP(S) destinations. Analyzed destinations reuse the complete current Phase 2/3/4/8/9 website pipeline, Phase 6 risk and Phase 7 explanations. QR/OCR media callbacks share the same normalized destination cache.

Fragments are deduplicated; query semantics remain distinct. One destination per message, 25-second website worker and remaining-budget checks bound work. Private destinations are blocked by existing SSRF validation/DNS pinning. Discovery source and omitted/failed status remain visible. Dynamic browser execution remains NOT_IMPLEMENTED. An inventory is not a claim that all URLs were scanned.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
