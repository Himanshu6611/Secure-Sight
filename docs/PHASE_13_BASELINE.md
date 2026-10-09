# Phase 13 code baseline

Audit started 9 October 2026 against the existing dirty Phase 0–12 workspace; no prior changes were reset. This is a code review and controlled local verification, not a penetration-test claim.

Inspected the phase reports, application factory/routes/middleware/configuration/logging, dashboard identity/SQLite/audit/export code, URL/DNS/pinned HTTP/JSON/TLS/WHOIS transport, crawl/history, email jobs/MIME/ZIP handling, media intake/decoder worker, model loader, requirements, Docker/Compose and existing tests. No repository AGENTS.md or CI workflow existed at baseline.

Verified existing controls: public-IP DNS validation and literal-IP pinned HTTP/TLS, redirect revalidation, compressed HTTP rejection and byte/time caps; MIME/part/body/attachment/ZIP limits; allowlisted image magic and disposable decoder processes with wall/output/CPU/memory caps; explicit unknown/partial outcomes; Phase 6/7 authority; tenant-filtered parameterized SQLite, encrypted content, role restrictions, CSRF and authenticated exports; shared Redis production rate/job storage, local concurrency caps, encrypted expiring bearer-job results; production configuration checks, sanitized exception logs, security headers; model metadata/hash/version checks before deserialization.

Verified gaps before Phase 13 edits:

| ID | Risk | Code evidence | Disposition |
| --- | --- | --- | --- |
| P13-01 | HIGH | `.dockerignore` omitted `instance/`; Docker uses `COPY . .`, potentially baking private DB/key/local credentials into an image | Exclude private runtime files |
| P13-02 | HIGH | `app/media/worker.py` inherited all environment variables for linked URL workers; application startup loaded `.env` and installed private persistence | Minimize environment and disable secret/persistence startup in analysis children |
| P13-03 | MEDIUM | Flask/provider JSON accepted duplicate keys, non-finite literals and deeply nested objects | Strict bounded parser and typed request contracts |
| P13-04 | MEDIUM | Scan semaphore hook ran before dashboard role/CSRF loading and included all POST API paths | Authorize/validate before reserving actual detector capacity |
| P13-05 | MEDIUM | Unicode CSRF input could raise TypeError; any failed bearer authentication could fall back to a cookie session | Bound ASCII CSRF/bearer input; explicit bearer identity takes precedence |
| P13-06 | MEDIUM | Decoder temp files used shared default temp directory; linked process initialization could write persistent local files | Per-job temporary workspaces and cleanup |
| P13-07 | MEDIUM | JSON providers had bounded transport but no provider-origin failure breaker | Bounded process-local provider circuit breaker |
| P13-08 | LOW | HTTP error codes varied; logs omitted actor and response error code | Stable common error codes and content-free actor/error events |
| P13-09 | Deployment gate | Child process limits are not filesystem/network privilege separation; dynamic browser execution is unavailable | Document honestly; no fabricated browser sandbox |
| P13-10 | Deployment gate | No production container/Redis/proxy test, signed artifact trust root, automatic history retention or external audit anchoring | Record remaining work and local scope |
| P13-11 | HIGH | Real linked-worker smoke returned overall PARTIAL with a low-risk LEGITIMATE candidate despite unavailable reputation/history | Central Phase 6 partial-intelligence safety guard, policy 6.2.1; preserve scores and historical snapshots |

Legacy `utils/model.py` contains joblib helpers but is not the active scan loader. The active `ml/inference.py` checks operator-owned metadata/hashes before loading; hashes do not authenticate a simultaneously replaced manifest. No user-supplied model file or shell command is accepted. Provider integration placeholders remain unavailable. Anonymous detector APIs are intentionally public; private objects are authenticated. Preserve that compatibility while applying least privilege to private data.
