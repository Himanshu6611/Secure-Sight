# Security controls and limits

URL validation rejects credentials, control characters, malformed ports/escapes, dangerous schemes and private/local/mapped/tunnel destinations. DNS uses bounded dnspython lifetimes, without global socket changes.

TLS, HTTP GET/HEAD and WHOIS connect to validated literal addresses. HTTPS retains original Host, SNI and certificate verification. Mixed public/private DNS answers are blocked. HTML allows three redirects and revalidates each destination. Environment proxies and implicit redirects/retries are disabled.

HTML retrieval has a total deadline, 1 MiB byte cap, successful HTTP status, required HTML content type and identity encoding. Responses/pools close on every path. DOM parsing limits nodes, depth and resources. Protocol-relative URLs and every credential form are inspected. JavaScript/forms do not execute; dynamic analysis explicitly reports unavailable.

Heavy API/form requests share capacity. APIs have 8 KiB payload limits and quotas; uploads have byte/format/pixel controls. Production refuses unsafe configuration and unavailable Redis.

Model loading validates version/schema/checksums and serialization environment. SHA256 detects accidental corruption, not malicious replacement of metadata and artifacts; trusted provisioning is required. No public model upload/training endpoint exists. Missing features/inference failures cannot yield a legitimate verdict.

Unknown reputation and unimplemented providers report UNKNOWN/UNAVAILABLE. Historical training-list matches are SUSPICIOUS, not confirmed current threats; non-hits cannot establish safety.

Jinja escapes content; scanned HTML is never executed. CSP, host/origin checks, no-store responses, safe errors and content-free structured logging remain active. Secrets are ignored and excluded from build context.

Infrastructure egress restrictions still matter. Public operation requires private/metadata-network blocking, verified TLS/proxy/Redis, trusted forwarding, resource/load tests and fresh model validation. The sync-worker watchdog is a final bound, not a cancellable job system.

No database/auth/passwords/JWT/roles/history exists. Unavailable email/image models report incomplete analysis. Image heuristics do not establish authenticity. External reputation APIs and isolated dynamic execution are not implemented and their absence is visible.

See [remediation evidence](REMEDIATION_20261008.md) for outstanding public-release gates.
