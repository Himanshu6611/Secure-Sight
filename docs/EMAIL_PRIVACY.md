# Email privacy and jobs

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

Raw emails and attachment bytes remain request/worker memory and are not stored in job records or logged. Public results retain bounded private snippets, domain identities, redacted URLs and hashes; treat returned results as private. JSON logs contain stage/status/duration/verdict and error codes, not raw mail.

POST /api/v1/email/analyze returns HTTP 202 with a random job ID and bearer token. Poll GET /api/v1/email/jobs/<job_id> with Authorization: Bearer TOKEN; absent/wrong tokens return 404, responses use no-store. Never put tokens in URLs. Development storage is bounded process memory. Production Redis records are Fernet encrypted with a key derived from the server secret; token hashes are constant-time compared. Two concurrent jobs and 16 records globally per Redis namespace; processing retention 600 seconds, completed retention 300 seconds. Trusted operators must secure Redis/TLS, server secrets and access to response data. There are no account-based ownership or background durable-worker guarantees.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
