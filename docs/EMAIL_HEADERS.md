# Header identity

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

From, Sender, Reply-To, Return-Path, To/Cc, Subject, Message-ID, Date, Received and authentication headers are inspected. Mailbox local parts and Message-ID are hashed. Domain relationships distinguish exact alignment, shared registrable domain, mismatch and missing information.

Unicode normalization, limited confusable skeletons, mixed Latin/Cyrillic/Greek, invisible characters and Punycode are contextual indicators. Third-party delivery services and identity mismatches alone do not establish phishing. Header inventory contains names and hashes, not full raw headers.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
