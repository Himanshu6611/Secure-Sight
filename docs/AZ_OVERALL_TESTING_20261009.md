# SecureSight A-to-Z overall testing

**Run date:** 2026-10-09  
**Scope:** Local Windows workspace, local HTTP app at `127.0.0.1:5001`, deterministic automated tests, and an isolated Docker image. No real phishing destination, third-party image-search provider, or production deployment was contacted.

## Result

**Engineering checks pass; public-release acceptance remains blocked.** The repository quality runner passed, the full suite passed, and the current container built and passed its isolated smoke. Several checklist items require independent real-world data or production infrastructure that is not configured. The image-origin classifier, deepfake detector, nudity detector, and automated public image-match search are not available, so their results remain unknown/unavailable rather than guessed.

## Checklist results

| Area | Status | Evidence / limitation |
|---|---|---|
| Application startup and pages | PASS / PARTIAL | The current Docker image started in isolation and `/api/v1/ready` returned HTTP 200. Local homepage, all three guides, privacy, security, health, and readiness endpoints returned HTTP 200 with CSP and `X-Content-Type-Options: nosniff`. Current frontend JS/CSS assets were served. Full interactive navigation across multiple viewport sizes was not automated. |
| URL and domain analysis | PASS / PARTIAL | Full offline regression and URL-model replay passed. Missing URL and `file:` URL were rejected (400); GET on the scan endpoint returned 405. Known malicious URLs were not contacted; reputation, WHOIS/RDAP, redirects and provider outages are tested with safe deterministic fixtures. |
| Website scanner | PASS / PARTIAL | Regression tests cover crawl limits, redirects, safe fetching, SSRF/private-address blocking, timeouts and provider failures. No live public target was fetched in this run; dynamic script execution remains intentionally out of scope. |
| Email analysis | PASS / PARTIAL | A harmless synthetic `.eml` completed via the live local API (202 submission, 200 job result, `PARTIAL/UNKNOWN`, zero links and attachments). Automated cases cover malformed/authentication/link/attachment behavior. No real mailbox or live phishing mail was used. |
| Image analysis | PASS / PARTIAL | Local API accepted JPEG, PNG and WebP in 1.09–1.22 seconds each and returned `PARTIAL/UNKNOWN`. Empty and unsupported SVG/mismatched files were rejected. Signed C2PA tests cover trusted, untrusted and tampered manifests; an untrusted test credential surfaced its declared generator as unverified. A validated general AI-image/deepfake classifier is unavailable; SynthID is a manual external check, not integrated. No nudity classifier is configured. |
| Public image-match search | UNAVAILABLE | No approved search provider is configured. The image is not submitted to a search service; no claim of exhaustive matches is made. |
| Machine-learning evaluation | PASS / PARTIAL | Saved URL-model replay, calibration, grouped-split/leakage checks and evaluation gates passed. Historical offline holdout: accuracy 98.53%, precision 99.40%, recall 97.19%, F1 98.28%, FPR 0.45%, FNR 2.81%, ECE 0.0069. These figures describe the saved URL dataset/model evaluation only, not live web performance or image/email accuracy. A prospective external holdout is unavailable. |
| Security | PASS / PARTIAL | Full security regression suite passed. Bandit reported zero findings; source inventory scanned 343 files with zero findings; pip audit reported no known vulnerabilities; npm audit passed. Docker Scout’s latest recorded image scan still lists six HIGH OS-package findings (expat, libxml2, cyrus-sasl2, zlib) and zero critical; that existing release blocker has not been resolved in this run. |
| API/backend | PASS | Local checks verified health/readiness, method and malformed-parameter handling, SSRF-safe URL validation, image upload contracts, and authenticated email-job polling. Responses returned structured errors without exposing tracebacks. |
| UI/results/accessibility | PASS / PARTIAL | React production build and lint passed; packaged assets passed the container smoke. Image results distinguish origin from threat review. Full screen-reader, keyboard, and responsive browser E2E/accessibility audit was not run. |
| Performance/reliability | PASS / PARTIAL | Quality benchmark: 200/200 serial dashboard requests succeeded, p95 7.51 ms, zero outbound calls in the benchmark. Image API fixture scans completed in about 1.1–1.2 seconds. Concurrent whole-pipeline load, production Redis/queue behavior, native/RSS peak memory, and saturation were not measured. |
| Deployment | PASS / BLOCKED | Production Compose syntax passed using nonfunctional placeholder values. Current Docker image built successfully and isolated smoke passed readiness, React assets, non-root UID, read-only filesystem, no network, and clean SIGTERM. Real Redis/secrets/TLS/proxy/egress/backup/restore and hosted CI were not exercised. |

## Executed commands and artifacts

- `python -m quality.run --stage all` — PASS; coverage gates 92.18% statements / 84.74% branches, zero failures or skips. Full gate evidence is in `reports/phase14_20261009/`.
- `python -m quality.run --stage report --profile release` — expected BLOCKED; six evidence gates are unavailable: prospective external holdout, campaign/temporal leakage evidence, production worker isolation, production load, full UI accessibility E2E, and historical PayPal redirect regression.
- `.venv/Scripts/python.exe -m pytest -q` — **851 passed**, 26 scikit-learn deprecation warnings.
- `npm run build` and `npm run lint` — PASS.
- `docker buildx build --load --tag securesight:az-test .` — PASS.
- `scripts/docker_smoke.ps1 -Image securesight:az-test` — PASS.
- `docker compose -f compose.production.yml config --quiet` — PASS with review-only placeholder environment values; no production credentials were used.

## Release decision

Do not describe SecureSight as fully production-ready or as providing universal AI-image/deepfake detection. Before public launch, resolve the recorded HIGH container findings, configure and test production Redis/secrets/TLS/egress/retention/backup, run representative production load and accessibility/browser checks, and acquire a provenance/licensed source-disjoint image corpus plus an independent prospective URL/web holdout. Keep unsupported media-origin and image-match results explicitly unknown until a validated detector/provider is approved and evaluated.
