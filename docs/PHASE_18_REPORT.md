# Phase 18 — Docker and production deployment foundation

## Architecture discovered

The service is a Flask 3.1 application running on Python 3.12 and Gunicorn. It loads an approved local scikit-learn model bundle and uses Tesseract for OCR. Persistent private investigations are encrypted in SQLite; there is no migration framework. Redis is an external shared dependency for production rate limiting and email-job coordination. The application listens on container port 5000. `/api/v1/health` is liveness; `/api/v1/ready` checks readiness. There is no checked-in production reverse proxy, TLS/DNS configuration, firewall policy, managed database, or monitoring stack.

## Implemented

- Restricted the Docker context to runtime source/model/data inputs, excluding local env/configuration, SQLite state, datasets, tests, reports, and legacy model artifacts.
- Pinned the Python 3.12 Trixie base image by digest and retained the exact runtime lock. The multi-stage image verifies `pip check` and the model bundle during build; it runs as UID 10001.
- Added separate single-host production Compose settings: loopback-only ingress for a host reverse proxy, named durable state volume, read-only root, bounded tmpfs/process/memory/CPU, dropped capabilities, no-new-privileges, and readiness health check.
- Added production architecture, environment, artifact inventory, smoke checklist, and recovery/rollback instructions. The Render descriptor remains manual and its free service does not provide durable dashboard data.
- Added an isolated Docker smoke script and CI build/smoke/image-scan gates. CI itself has not run in this turn.
- Enabled BuildKit SBOM and provenance generation in the CI image build.

## Validation results

| Check | Result | Evidence |
| --- | --- | --- |
| Docker build | PASS | `docker buildx build --build-arg PIP_DEFAULT_TIMEOUT=180 --sbom=true --provenance=mode=max --load --tag securesight:phase18-review .`; runtime lock installed, `pip check` passed, model SHA/version validation passed. |
| Image | PASS | Local image ID `sha256:4ccec82a2c86f3926c253caa4c357319f3ecee7ed02e25abe860af896fce51c9`; 559,343,274 bytes; 300 packages indexed. |
| Compose parsing | PASS | Production and development manifests parsed with `docker compose config --quiet` using explicitly nonfunctional review-only values. |
| Container readiness/security/shutdown | PASS | `scripts/docker_smoke.ps1` returned PASS for isolated `/api/v1/ready`, UID 10001, read-only root, no network, and clean SIGTERM exit. This used `APP_ENV=testing`, not production secrets or Redis. |
| Image scan | FAIL / release blocker | Docker Scout found 0 critical, 6 high, 0 medium/low vulnerabilities in `expat`, `libxml2`, `cyrus-sasl2`, and `zlib`; Scout listed no fixed versions. The workflow now fails on critical/high findings. |
| Source test suite | NOT RUN | Only container/deployment checks were run in this turn; the existing CI workflow retains the project quality suite. |
| Production Redis/TLS/proxy/egress | NOT RUN | No deployment infrastructure or credentials are configured here. |
| Durable-volume replacement and backup/restore | NOT RUN | Documented procedure only; no recovery rehearsal or retention policy has been supplied. |
| Hosted CI execution | NOT RUN | CI steps were added to the existing self-hosted quality workflow but were not dispatched. |

## Topology and remaining owner work

Single-host Flask/Gunicorn with one worker, loopback binding, a host-managed HTTPS reverse proxy, external private Redis, and a named volume for encrypted dashboard state. No worker or database ports are published. The Compose bridge still permits outbound traffic; application SSRF validation remains, but an egress firewall/proxy must be configured and verified before accepting public untrusted URL scans.

Before public release, resolve or formally review the six high image findings, provision real independent secrets and private Redis, choose the production host and durable backup target, configure TLS/reverse proxy/firewall and restricted egress, decide retention/restore objectives, and rehearse restore plus rollback in staging. The 2 GiB/2 CPU limits are provisional rather than workload-measured. Do not use the Render free descriptor for persisted dashboard investigations.

**Status: partially complete.** The image builds and passes isolated container checks, but scan findings and deployment-owner prerequisites block a production-ready claim. No public deployment, DNS/TLS change, or external credential was applied.
