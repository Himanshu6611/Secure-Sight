# Phase 13 implementation and verification

Date: **9 October 2026, Asia/Calcutta**. Status: **PARTIAL — local backend hardening and regression verification completed; public-production security gates remain.** No penetration-test, legal-compliance or detection-accuracy certification is claimed.

## Changes

Code baseline/risk register and threat model: PHASE_13_BASELINE.md and THREAT_MODEL.md. Fixed private instance/SQLite/key/credential Docker exclusions. Analysis children now use a minimal environment and ephemeral per-job cwd/temp workspace; linked URL workers skip dotenv, service identity/Redis/dashboard credentials and private persistence. Start-failure cleanup and existing wall/CPU/memory/output controls are tested.

Added strict bounded JSON to API intake/media context/provider responses/worker output: reject duplicates, non-finite/overflow numbers and excessive depth/collections/nodes. Typed scan/email/error contracts augment existing exact-field and feature validation. Supplied upload extensions must match magic/MIME before decoding. WHOIS validates query domains; HEAD reuses the shared pinned pool. Existing DNS/TLS/redirect/HTML/robots/crawl/RDAP/QR/email SSRF controls remain enforced.

Identity/CSRF precede detector-slot reservation; private workflow writes no longer occupy scan slots. Added configurable authenticated account/token limits per detector endpoint. Invalid supplied bearer credentials cannot fall back to cookie identity; bounded ASCII CSRF avoids Unicode-triggered internal errors. Common errors now have stable codes/correlation, logs include actor ID/role/error code, and development INFO access logs containing URL queries are suppressed. Bounded provider-origin failure circuits recover with one probe; failure remains unavailable.

Real linked-worker smoke additionally exposed PARTIAL with a low-risk LEGITIMATE candidate. Phase 6 policy **6.2.1** now withholds LEGITIMATE when any applicable intelligence stage is incomplete; low-risk partial results become UNKNOWN, while corroborated threat verdicts remain available. Added SAFETY_WITHHELD_PARTIAL provenance and four regression cases. Risk values/thresholds/models were not changed, and existing stored snapshots retain their original policy version. Generic confidence/static-scope notices are advisory; the guard consumes actual stage availability.

Phase 6/7 remain verdict/scoring and explanation authorities. No model retraining, threshold tuning, feedback-ground-truth promotion, historical snapshot rewrite or public deployment occurred. Anonymous detector access and tenant-shared private history remain.

## Results

| Check | Actual result / scope |
| --- | --- |
| Final suite | **731 passed**, **46 new Phase 13 tests**, zero failed/skipped, 26 existing sklearn/SciPy warnings; **88.29 seconds** |
| Hardening statement coverage | **86.34%**, app.security/app.middleware/app.media.worker; not whole-repository coverage |
| Local HTTP probes | **16/16 passed**, fixed localhost only; no case/investigation created or credentials recorded |
| Runtime Bandit 1.7.10 | **0 findings**, app/utils/ml, existing reviewed nosec annotations retained |
| Broad Bandit including scripts | **21 warnings retained/reviewed**: 18 B101 validation/smoke assertions, two B404/B603 fixed-vector operator calls, one B310 fixed-loopback smoke URL; non-runtime tool warnings |
| Fatal Flake8 / pip check / diff check | PASS; existing Git LF/CRLF notices |
| pip-audit 2.10.1 | **0 known vulnerabilities** in resolved runtime/media/email/development requirements at audit time; CycloneDX **91 components** |
| Working-tree secret heuristics | **0 findings**; format/literal scan, no secret values output; history/fixtures/private files excluded |
| Installed license/dependency inventory | **93 packages**, metadata/environment freeze saved; legal approval not established |
| Docker/container runtime | **NOT VERIFIED**, Docker CLI present but Linux engine daemon unavailable; no image build/Linux isolation run |

Targeted overlapping batches passed 175, 118, 171 and 217 tests during fixes; do not add them to unique totals. Tests cover roles/tenant/IDOR/export, mass assignment, bearer/CSRF, strict API/provider JSON, DNS rebinding/private redirects, worker environment/workspace/start cleanup, upload mismatch/ZIP/MIME/resource caps, WHOIS injection, rate/Retry-After, safe logging and failure-never-safe. No protections were disabled or new dependencies introduced. Optional image-ML extras are outside the dependency audit and active inference. SBOM and installed package inventories have different scopes.

Final real disposable linked-worker smoke against benign example.com returned PARTIAL/UNKNOWN under policy 6.2.1 in 7.984 seconds. It neither persisted an investigation nor inherited service credentials. Local probes were rerun after the final server restart and again passed 16/16.

## Completion and limits

Verified: baseline/threat model, server authorization/tenant checks, shared safe outbound HTTP policy, intake/resource/queue/rate caps, safe application errors/logging, local static/dependency/secret checks and security regressions, explicit failed/partial results.

Remaining public-release gates: actual low-privilege filesystem/network worker sandbox and browser isolation; Docker/Unix runtime verification; secured production Redis/proxy/TLS/multi-worker stress and external DAST; signed artifact trust root/transitive platform hash lock; Git-history/old-image secret review and legal/license assessment; external audit anchoring; organization-specific automatic retention and dashboard-key re-encryption migration. Process limits and temporary directories are not OS isolation: children retain host account permissions. Hashes cannot authenticate a replaced model plus manifest. License metadata is not legal clearance; the secret scan is not enterprise certification.

Earlier representative accuracy/calibration and Phase 8–11 capability gaps remain. No 100% accuracy or public-production readiness is claimed. Core implementation is available for local testing at http://localhost:5000/dashboard.

## Documents and evidence

Required documents: PHASE_13_BASELINE.md, THREAT_MODEL.md, API_SECURITY.md, SSRF_DEFENSE.md, AUTHORIZATION_MODEL.md, UPLOAD_SECURITY.md, SECRETS_MANAGEMENT.md, DATA_RETENTION.md, SECURITY_TESTING.md and this report.

Evidence under reports/phase13_20261009: tests.log, junit.xml, coverage.json, local_dast.json, linked_worker_smoke.json, bandit_runtime.json, bandit.json, dependency_sbom.json, dependency_audit.log, supply_chain.json, environment_freeze.txt, flake8.log, pip_check.log, diff_check.log and verification.json. Reusable tools: scripts/security_probe.py and scripts/security_inventory.py. Private login details stay in instance/dashboard-login.txt, excluded from source/build/report output.
