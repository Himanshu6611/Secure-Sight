# Investigation workspace

Phase 12 contract version: **12.0**.

/dashboard and /dashboard/investigations/<id> provide overview, investigation history, separate verdict/risk/severity/confidence/completeness/ML fields, backend reasons with evidence links, missing intelligence, contradictions, timelines and relevant modular panels. Domain, website, redirects, history, brand, email, authentication, attachments, media metadata/quality/forensics/models, OCR, QR, C2PA and campaign panels appear only when upstream data exists.

No external webpage, email HTML, iframe, attachment or script is rendered or executed. Raw email body snippets are intentionally not retained; sanitized original HTML previews are unavailable. OCR text is private extracted evidence. C2PA absence is not fabrication; presence is not truthfulness. Image risk/confidence can describe a linked destination and its assessment_scope is displayed. Backend zeros and nulls retain distinct meanings. Historical snapshots are immutable except separate analyst assessment metadata.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
