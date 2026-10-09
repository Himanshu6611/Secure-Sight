# Evidence graph UI

Phase 12 contract version: **12.0**.

SVG nodes and backend relationships are interactive and keyboard focusable. Entity filters and bounded pages expose node details, edge relationships, supporting source fields/provenance and any backend evidence references. Full graph and entity counts remain visible; omitted cross-page edges are counted.

No fake relationships or detection findings are generated. Existing email/media/brand graphs are namespaced and merged only from their actual backend outputs; dangling edges are omitted. Nodes can be inspected with Enter/Space or pointer. The current graph uses a deterministic grid, not a force-layout engine. Readable entity details accompany the visual graph; limit=100 maximum and graph page size=50 keep browser work bounded.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
