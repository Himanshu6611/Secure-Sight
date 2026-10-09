# SecureSight remediation follow-up — 2026-10-09

## Changes completed

- Refreshed both Python build/runtime stages to immutable `python:3.12-slim-trixie` digest (`sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe`). The rebuilt image passes the isolated smoke test; the fresh scan below shows its remaining CVEs.
- Changed production Compose to mount the Flask key, dashboard encryption key, and authenticated Redis URL as read-only Compose secrets. Only secret-file paths are interpolated; secret values no longer appear in the Compose-generated environment. The application already supports bounded `*_FILE` secret loading. For file-backed Compose secrets, source files must be readable by UID `10001`; the protected-directory/file-mode setup is documented.
- Added tests for secret-file trimming, empty and oversized values, embedded line breaks/control characters, and conflicting direct/file configuration.
- Confirmed `.env` is ignored and not tracked by Git. No secret values were printed or added to source control.

## Verification

| Check | Result |
| --- | --- |
| `tests/test_runtime_secrets.py` | PASS — 8 tests |
| `tests/test_security.py tests/test_phase13_security.py` | PASS — 125 tests |
| Full test suite | PASS — 859 tests, 0 failures/errors/skips; 26 existing SciPy/scikit-learn deprecation warnings |
| Engineering quality gate | PASS — lint, strict gate typing, frontend build/lint/audit, model replay, tests, security, dependency audit and benchmark; critical coverage 92.27% statements / 84.85% branches |
| Production Compose syntax/environment inspection | PASS using nonfunctional review-only values and `.env.example` only as an existing secret-file path; rendered service environment includes secret-file paths and no secret-value variables. This did not validate live secrets or services |
| `docker buildx build --load --tag securesight:az-remediation .` | PASS |
| `scripts/docker_smoke.ps1 -Image securesight:az-remediation` | PASS — readiness, packaged frontend assets, non-root UID, read-only filesystem, no network, graceful shutdown |
| Playwright + axe browser E2E | PASS — 7 tests, 0 failures, 0 flakes, 0 skipped; `browser_e2e.json` retained |
| Fresh Docker Scout scan of rebuilt image `sha256:6841f5e31420f19d72e03bb8987216bfabdb0eb05be50500aee4484e5256b46d` | FAIL — 1 critical + 10 HIGH across 6 packages; raw SARIF retained; CI threshold remains enforced |
| Release profile | BLOCKED — 11 critical/high scanner findings plus seven unavailable required evidence gates (independent holdout, campaign/temporal evidence, worker isolation, production load, historical PayPal replay, approved retention/restore, production infrastructure validation) |

## Container findings and package chain

The fresh Docker Scout scan is retained at `reports/phase14_20261009/docker_scout.sarif`. The latest rerun scanned immutable image digest `sha256:6841f5e31420f19d72e03bb8987216bfabdb0eb05be50500aee4484e5256b46d` and reports **11 critical/high CVE results across 6 Debian packages: 1 critical and 10 high**. CI retains the SARIF and fails on scanner exit code 2 rather than discarding the machine-readable evidence.

| Package / installed version | Docker Scout findings | Debian/vendor disposition as checked 2026-10-09 |
| --- | --- | --- |
| `krb5` `1.21.3-5+deb13u1` | HIGH: CVE-2026-107778 | Scout reports no fixed Debian version. No Trixie package-level fix was verified; keep open. |
| `cyrus-sasl2` `2.1.28+dfsg1-9` | HIGH: CVE-2026-107161 | Scout reports no fixed version; Debian package tracker does not yet provide a disposition for this CVE. Keep open. |
| `gnutls28` `3.8.9-3+deb13u4` | HIGH: CVE-2026-67693, CVE-2026-95184, CVE-2026-95209; CRITICAL: CVE-2026-95210 | Scout reports generic affected range `>0`, which is not Debian-aware applicability evidence. The CVE descriptions identify upstream 3.8.13; Debian's tracker does not yet list these newly published CVEs. A different upstream 3.8.13 CVE is explicitly marked not affected in Trixie, demonstrating that upstream-version matching alone can be wrong. These four results need Debian/vendor package-level adjudication; the critical remains release-blocking in CI. |
| `libxml2` `2.12.7+dfsg+really2.9.14-2.1+deb13u3` | HIGH: CVE-2026-74860, CVE-2026-86140 | Debian marks both vulnerable in Trixie and fixed in forky/sid at `2.15.4+dfsg-1`; no supported Trixie fix was listed. |
| `expat` `2.8.3-1~deb13u1` | HIGH: CVE-2026-93990, CVE-2026-77214 | Debian marks `CVE-2026-93990` fixed in forky `2.8.4-2`, but `CVE-2026-77214` remains vulnerable through forky and fixed only in sid `2.9.0-1`; Trixie has neither fix. |
| `zlib` `1:1.3.dfsg+really1.3.1-1+b1` | HIGH: CVE-2026-85091 | Debian lists Bookworm, Trixie, Forky, and Sid vulnerable with no fixed version. Upstream's affected range starts at 1.3.1.2, newer than Debian's nominal upstream 1.3.1; Debian still tracks the package as vulnerable, so this needs maintainer adjudication rather than a local waiver. |

The runtime dependency chain ties these libraries to retained functionality: Tesseract needs fontconfig/Expat, libarchive/libxml2 and zlib; Tesseract also depends on libcurl, which depends on libldap and Cyrus SASL. These package-level matches do not establish application call-site reachability. Removing packages is not a valid fix where transitive consumers still need them. The refreshed and rebuilt Trixie image did not remediate the findings; moving production to testing/unstable or compiling arbitrary patched libraries would be unsupported and unvalidated. The older Bookworm image was scanned and had eight HIGH findings, so switching to it would worsen the result.

The Debian dispositions above are supported by the [Debian libxml2 tracker](https://security-tracker.debian.org/tracker/source-package/libxml2), [Debian Expat tracker](https://security-tracker.debian.org/tracker/source-package/expat), [Debian zlib tracker](https://security-tracker.debian.org/tracker/source-package/zlib), [Debian Cyrus SASL tracker](https://security-tracker.debian.org/tracker/source-package/cyrus-sasl2), and [Debian GnuTLS tracker](https://security-tracker.debian.org/tracker/source-package/gnutls28). Debian's [Trixie GnuTLS security advisory](https://security-tracker.debian.org/tracker/DSA-6281-1) confirms the installed revision contains backported security fixes for older 2026 CVEs; [NVD](https://nvd.nist.gov/vuln/detail/cve-2026-95210) currently describes CVE-2026-95210 as an upstream 3.8.13 issue but has no enriched affected-product data. Package-level applicability for the four new results is still unconfirmed.

The scanner package locations identify Debian package metadata, not the exact application call sites. This is a package-level disposition, not proof that every vulnerable code path is reachable. Do not waive these findings solely on that basis.

The follow-up source audit now records the exact installed/source revisions, inspected Debian source, patch inventory, available source/binary hashes, vendor status, action, verification and reviewer decision per CVE in [`reports/cve-dispositions/20261009_source_dispositions.md`](../reports/cve-dispositions/20261009_source_dispositions.md). The audit confirmed that the zlib `gz_vacate()` function named in CVE-2026-85091 is absent from the exact Trixie source and installed binary, but Debian still tracks the source package as vulnerable and has not accepted a not-affected disposition; Scout remains enforced. It also confirmed that the libxml2 Python SAX binding implicated by CVE-2026-74860 is not installed/importable in this application image; the shared libxml2 library remains for OCR dependencies and the scanner finding remains visible pending package-level vendor adjudication. Other findings remain open unless and until a supported fix or authoritative not-affected decision is verified.

### Verification rerun

The current working tree passed all **859 tests** with no failures, errors, or skips (26 existing SciPy/scikit-learn deprecation warnings). Engineering gates passed; frontend production build, lint, high-severity npm audit, model replay/regression, Bandit, source inventory, pip consistency/audit, benchmark, and all **7 Playwright/axe tests** passed. The existing browser setup was retained; the tests were rerun directly. Docker build and isolated smoke passed. A bounded local load smoke sent 500 readiness requests at concurrency 10 with zero failures; latency and scope are recorded in `reports/phase14_20261009/local_concurrent_smoke.json`. It does not close the production load gate. Fresh Docker Scout scanned rebuilt image `sha256:6841f5e31420f19d72e03bb8987216bfabdb0eb05be50500aee4484e5256b46d` and again found **1 CRITICAL + 10 HIGH across 6 packages**. Scout exited under its enforced severity policy and wrote the current raw SARIF to `reports/phase14_20261009/docker_scout.sarif`; no exclusion or package metadata change was made. The release profile was rerun and remains **BLOCKED**: the scanner gate fails and all seven production/independent-evidence gates remain unavailable. Manual screen-reader review was not performed; automated axe is not a substitute.

## Still requires external evidence or infrastructure

- No independent prospective URL/page holdout or campaign-temporal dataset was supplied. Historical URL-model metrics remain offline-only and were not changed.
- No production host, authenticated Redis endpoint, TLS reverse proxy, egress firewall/proxy, secret-manager account, or backup target is configured. Compose syntax does not prove their security or availability.
- No production-like concurrency/load or worker isolation environment is available. Existing Docker smoke verifies basic container restrictions, not host-level isolation or capacity.
- A Playwright/axe browser harness now runs seven local tests covering public routes, URL/email/media scanner states, accessible errors/loading/results, keyboard operation, accepted/rejected uploads, 360px layout, and automated WCAG 2.1 A/AA checks on routes and all three scanner modes. The current run passed 7/7 with zero flakes/skips; JSON/HTML reports and failure traces are configured. CI installs Chromium and runs this suite in the protected self-hosted workflow. This automated run does not replace manual assistive-technology review. The historical PayPal redirected path remains redacted, so the exact previous false positive cannot be reproduced without that safe fixture; the benign root-domain replay does not close it.
- Automatic age-based deletion of investigations, backup retention, and restore rehearsal still need an operator-approved policy and separate recovery environment. Existing tenant purge and storage limits do not replace a retention schedule.

No live malicious destination was contacted, no external image service received user data, no production secret was provisioned, and no public deployment was performed.
