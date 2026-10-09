# Evidence explorer

Phase 12 contract version: **12.0**.

The evidence adapter preserves original IDs, source values, normalized IDs for nested results, category, indicator, severity, confidence, source version where available, phase, observed timestamp, recorded timestamp, artifact hashes and type. OBSERVED, INFERRED, MODEL_DERIVED, EXTERNAL, MISSING and CONTRADICTORY remain distinguishable. Phase 7 reason references link to actual stored evidence. Missing references are explicitly labeled.

Server-side evidence filters include category, severity, source, phase, type, confidence minimum (backend 0–1 scale), since/until and pagination. A missing observed timestamp is not replaced by a scan timestamp. Source version can remain null when the source does not publish it. Root confidence indexes use the backend 0–100 scale, separate from individual evidence confidence. Displaying a value does not turn it into a confirmed fact.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
