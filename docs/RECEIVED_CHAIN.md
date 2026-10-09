# Received and timestamp analysis

Phase 11 feature version: **11.0**. Status: **PARTIAL**.

At most 32 Received hops are inspected for public IPs, external hostnames and timestamps. Private IP values are redacted. Reverse chronological order, future Date and Date-after-receipt anomalies are recorded.

All uploaded hops are UNTRUSTED; there is no trusted receiving boundary. Reverse DNS is UNAVAILABLE and no attacker-specified host resolution is performed for hop attribution. Date inconsistencies are contextual and cannot prove maliciousness.

Implementation: `app/email/`; integration: `app/api/v1.py`, `app/media/`, `app/risk/engine.py`, `app/explanations/engine.py`. Verification: `tests/test_phase11_email.py`; [overall report](PHASE_11_REPORT.md).
