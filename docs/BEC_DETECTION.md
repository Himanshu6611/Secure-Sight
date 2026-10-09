# BEC contextual evidence

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

A BEC candidate requires a financial action plus bank-change or executive/secrecy context, together with urgency or Reply-To mismatch. A Phase 6 suspicious floor requires this combination and an identity anomaly.

Candidate means review evidence, not proven fraud. Legitimate invoices, password resets, urgent work and third-party senders do not become phishing from keywords alone. Trusted conversation history, known vendor accounts and recipient baselines are unavailable. Rules have not been calibrated against representative public email traffic.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
