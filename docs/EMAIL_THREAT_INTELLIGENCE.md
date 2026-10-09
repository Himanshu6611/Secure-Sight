# Email threat intelligence

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Original EML/raw MIME flows through an isolated bounded parser/authentication worker, sender intelligence, full website handoff, Phase 10 media, correlation graph, Phase 6 scoring and Phase 7 explanations. PDF, DOCX and XML exports are now passively text-extracted in an isolated worker before the same body/link analysis; their original transport authentication is unavailable. Feature version is 11.0; existing URL feature schema/model contracts remain unchanged. Results are PARTIAL with unavailable providers explicitly recorded.

One distinct destination and one image per message are analyzed; extra artifacts remain inventoried with resource-limit status. The async budget is 90 seconds; the HTML path is 38 seconds. Campaign batches accept at most three explicitly submitted messages within one 90-second budget.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
