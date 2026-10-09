# Production deployment smoke checklist

Run these operator checks after deploying a reviewed image digest to a private staging host configured with the same TLS proxy, Redis policy, volume permissions, and secrets as production. Do not use public customer data for the first deployment.

1. Confirm the deployed container reports the expected immutable digest and runs as UID `10001`; verify the root filesystem is read-only and only `/tmp` and the named state volume are writable.
2. Request `/api/v1/ready` through the reverse proxy. Confirm HTTP 200, correct HTTPS canonical origin, and valid certificates. `/api/v1/health` is only a liveness check and does not prove model or Redis readiness.
3. Exercise representative URL, email, and file scans with benign fixtures. Check stable response schemas and bounded error behavior. Verify the application does not disclose submitted content in logs.
4. Verify rate limits persist across a container restart, demonstrating that Redis is shared and reachable.
5. Provision an initial dashboard user through the container CLI. Confirm authenticated dashboard access, tenant separation, CSRF enforcement, logout, and audit-chain validation. Do not place passwords or bearer tokens in shell history.
6. Create a backup, restore it to a separate test volume, run `dashboard-audit-check`, and confirm the expected encrypted records are accessible with the escrowed key.
7. Confirm unauthenticated private dashboard pages are not indexed, public robots/sitemap/canonical tags match the approved domain, and `SEO_INDEXING_ENABLED` remains false until public release sign-off.
8. Exercise reverse-proxy body/time limits, request IDs, TLS forwarding, restart behavior, and the documented previous-digest rollback on staging.

This is a release checklist, not evidence that a public deployment, disaster recovery exercise, performance benchmark, or end-to-end scan review has already passed. Record build digest, operator, date, and outcomes before release.
