# Attachment safety

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

MIME, filename and magic are compared; executable/double extensions, OLE/macro-capable formats and suspicious ZIP members are recorded. ZIP central directories are inspected without filesystem extraction. Small TXT/XML/RELS entries may yield URLs without XML entity processing.

ZIP limits: 64 members, 1 MiB single expanded entry, 2 MiB combined declared expansion, compression ratio 100; URL text reads at most 64 KiB. Traversal, encrypted/nested archives and macros are explicit partial indicators. Opaque PDF/OLE and unsupported archive formats are not fully analyzed. No document, macro, archive member or executable is run.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
