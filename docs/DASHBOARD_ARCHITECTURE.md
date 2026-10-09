# Dashboard architecture

Phase 12 contract version: **12.0**.

Phase 12 consumes existing URL, email and media results through bounded adapters in app/dashboard/contracts.py. It never calls model inference, crawling or scoring on investigation reads. Phase 6 owns the verdict, severity, risk and confidence; Phase 7 owns explanations. URL/media API responses and HTML scan results are captured only for authenticated ADMIN/ANALYST/API_CLIENT principals. Async email jobs capture their authorized submitter, independent of later browser sessions. Anonymous results are not persisted.

SQLite/WAL provides indexed tenant metadata; Fernet encrypts private subjects, complete bounded projections, entity values, telemetry and cases. Search terms are keyed hashes. API contract version 12.0 has Python TypedDict definitions in app/dashboard/types.py. Presentation panels retain upstream schemas, rather than pretending missing fields exist. Graphs are bounded to 512 nodes/1024 edges, evidence to 1024 rows and records to 1 MiB. Current deployment is one host with a shared SQLite path/key, not an enterprise distributed datastore.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
