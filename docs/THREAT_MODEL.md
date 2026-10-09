# SecureSight threat model

Phase 13, 9 October 2026. Assets: private email/media/OCR evidence, investigation/case content, account credentials, job capabilities, encryption/signing keys, approved model/config files, backend capacity and authoritative Phase 6/7 output.

Trust boundaries: browser/API → bounded Flask intake → identity/CSRF/roles → tenant SQLite; detector → pinned outbound gateway → hostile DNS/sites/providers; parser → disposable decoder process → untrusted MIME/image bytes; operator → local models/config/secrets; dependency/build context → runtime image. SQLite tenants share an operator-managed host, not separate OS accounts.

| Actor / attack | Control / evidence | Residual risk |
| --- | --- | --- |
| Anonymous user reads private objects | Require decorators and tenant predicates; Phase 12/13 IDOR tests | Public detectors intentionally remain anonymous |
| Viewer/analyst escalates role or changes verdict | Operator-only account commands, field allowlists, separate feedback; mass assignment and role tests | Host/operator compromise is outside HTTP RBAC |
| Hostile DNS/redirect/QR/email URL reaches metadata | All HTTP paths use validated public literals, TLS hostname checks and redirect revalidation | Deployment egress firewall still required as defense in depth |
| Malicious MIME/image/ZIP exhausts decoder | Byte/part/depth/pixel/ratio limits, no extraction/execution, process resource/output/time limits | Decoder process retains host account filesystem/network permissions |
| Provider JSON poisons evidence or overloads service | HTTPS, bounded strict JSON, identity-specific RDAP normalization, failure circuit, explicit unavailable | A compromised public provider can lie; reported observations need corroboration |
| Attacker floods scans or polling | IP/account/endpoint quotas, scan slots, email queue/Redis leases, bounded pages | Distributed full deployment load not verified; some public GET utility routes only have query budgets |
| Stolen build context discloses private state | Docker ignores `.env`, instance/SQLite/key/credentials; working-tree secret checks | Old built images and Git history not scanned here |
| Model/manifest replaced together | Operator-controlled local bundle, schema/version/hash validation | Hashes are not signatures; trusted artifact root still needed |
| Stored XSS/title/OCR/email markup | Escaped Jinja, textContent, non-executing exports/CSP | Legacy main-page external CDN assets remain a supply-chain dependency |
| Audit/database tampering | HMAC chain, encryption, tenant SQL and content-free events | Tail truncation requires external anchoring; DB/key compromise defeats local protection |

Risk register: P13-01–08 and P13-11 in PHASE_13_BASELINE.md have local code fixes and regression evidence. P13-11 centralizes partial-intelligence safety withholding inside Phase 6 policy 6.2.1 without changing scores. P13-09–10 remain deployment gates: true OS/container sandbox and egress isolation, realistic Redis/proxy/container validation, signed artifact provisioning, externally anchored audit and enforced organization-specific retention. The earlier accuracy/calibration gaps remain separate. No legal compliance, penetration-test certification or accuracy guarantee is implied.
