# Remediation tracker

| ID | Severity | Role owner | Status | Retest / next evidence | Review |
|---|---|---|---|---|---|
| P15-001 | MEDIUM | backend-maintainer | FIXED | 3 nesting regressions; 39 targeted, 796 full tests pass | 2026-10-09 |
| P15-002 | MEDIUM reliability | model-maintainer | OPEN | 11/20 offline label changes; independent labeled evaluation required | 2026-11-09 |
| P15-003 | HIGH assurance gap | security-maintainer | OPEN; no acceptance | OS filesystem/network denial and isolation proof | Before any public release |
| LOCAL-ML-001 | Historical false-positive concern | model-maintainer | OPEN | Redacted redirected URL prevents full replay | 2026-11-09 |
| STAGING-LOAD/UI | Unverified release evidence | operations/frontend-maintainer | UNAVAILABLE | Controlled production-like load and browser security/E2E tests | Before any public release |

Owners are follow-up roles, not claimed messages or external assignees. No formal acceptance, waivers or blanket retries. Test temp data cleans normally; retained report artifacts are intentional. Never close a model finding merely because one root URL now passes.
