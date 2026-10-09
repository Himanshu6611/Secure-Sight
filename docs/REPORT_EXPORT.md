# Investigation export

Phase 12 contract version: **12.0**.

Authorized writer roles can export JSON or a self-contained encoded HTML report containing the stored summary, evidence, Phase 7 explanations, timelines, relevant domain/web/email/media/brand/history panels, graph, limitations and linked case notes. Analyst assessment remains distinct and unvalidated. Export/open actions enter the audit chain.

Exports are private, no-store downloads. Filenames contain the generated investigation ID, not malicious subjects/filenames. Responses are bounded to 2 MiB and synchronous because records are bounded to 1 MiB; a durable asynchronous export queue is not implemented. No PDF or attachment binary is included. Treat exported files as sensitive private data and manage copies/retention separately.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
