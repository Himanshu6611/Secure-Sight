# Cases and analyst workflow

Phase 12 contract version: **12.0**.

Authorized writers can create cases, attach up to 20 same-tenant investigations, add up to 64 verified evidence references, add notes, assign statuses, tag, mark reviewed and record investigation feedback. Cases use revision checks with HTTP 409 to avoid lost updates. Statuses: NEW, IN_REVIEW, ESCALATED, CONFIRMED, CLOSED, FALSE_POSITIVE. Feedback labels: TRUE_POSITIVE, FALSE_POSITIVE, TRUE_NEGATIVE, FALSE_NEGATIVE, UNKNOWN.

Notes are ANALYST_NOTE and feedback is validated_ground_truth=false. Neither changes system evidence, scoring or model training. Cases are intentionally shared among authorized members of one tenant. There is no cross-tenant administrator bypass. Case limit 500 per tenant; 100 notes per case, 4000 characters per note, 12 tags of 48 characters. The UI supports title, investigation/evidence linking, status, notes, reviewed state and investigation tags/feedback.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
