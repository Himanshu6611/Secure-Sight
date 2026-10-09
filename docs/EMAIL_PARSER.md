# MIME parsing

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Python BytesParser preserves the SHA-256 identity of original bytes and decodes plain/HTML multipart parts without rendering HTML. BODY_ONLY input is supported. Charset/parser defects and duplicate identity headers remain evidence.

Limits: raw email 2 MiB; header block 64 KiB; header line 8192 bytes; 128 headers; 20000 newlines; MIME depth 8; 32 parts; decoded body total 64 KiB; eight attachments; 512 KiB per attachment and 1 MiB combined. Worker wall cap 15 seconds, memory 1 GiB, CPU 10 seconds and output 2 MiB. No attachment execution or remote MIME resource loading.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
