# Purpose, access and deletion

No legal compliance claim is made. Operator must select a policy appropriate to real data before public deployment.

| Data | Purpose / access | Current retention / deletion |
| --- | --- | --- |
| Raw email/body/HTML/attachment bytes | Request/job analysis only | Not persisted in private investigations; in-flight memory/process temp files cleared when work finishes; no claimed guaranteed memory zeroization |
| Media/OCR/QR-derived results | Investigate returned evidence | Anonymous response only; authenticated projection encrypted with tenant access. Raw QR secrets omitted, OCR remains sensitive |
| Ephemeral email jobs | Capability-based completion polling | 600-second submission/progress TTL, 300-second completion TTL; encrypted Redis production; in-memory expiration cleanup locally |
| Investigations/entity indexes/telemetry | Private history/search/analytics | Maximum 2000 per tenant; explicit dashboard-purge deletes tenant content; no automatic age retention job |
| Cases/notes/unvalidated feedback | Analyst review collaboration | Encrypted tenant access, 500-case bound; tenant purge deletes; feedback is not verified ground truth or automatic retraining |
| Accounts/API credentials | Identity/access | Password/token hashes, explicit operator deactivation; no self-service account deletion endpoint |
| Audit/logs | Accountability/security diagnosis | No raw private content; audit remains after tenant content purge, no automatic audit age purge; operator chooses external log retention |
| Process-local web observations | Hash/count history, not global archive | Bounded Phase 9 cache/TTL (configured up to seven days), restarts lose history |
| Backups/downloaded exports | Recovery/user investigation | Outside live DB purge; access, retention and deletion are operator/user responsibilities |

SQLite deletion does not certify secure erasure of disk remnants/backups; encryption protects contents only while keys remain private. Cases and investigation content share a tenant workspace intentionally. Do not retain original emails or full HTML previews without a reviewed purpose/access/retention policy. Local synthetic verification fixtures/reports are test artifacts, distinct from production artifact retention.
