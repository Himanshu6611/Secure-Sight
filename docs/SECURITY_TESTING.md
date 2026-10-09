# Phase 13 security verification

Local Windows/Python 3.12.10 only. No public-target DAST or authorized penetration test was performed. Existing Phase 0–12 tests and new Phase 13 tests use deterministic offline transport fixtures; controlled HTTP probes target fixed localhost:5000 and an existing local analyst account, create no case/investigation content and record no credentials.

Commands and evidence (`reports/phase13_20261009`):

- `python -m pytest tests -q --junitxml=... --cov=app.security --cov=app.middleware --cov=app.media.worker --cov-report=json:...`: tests.log, junit.xml, coverage.json. Final totals are in PHASE_13_REPORT.md.
- Targeted fixes: 175 existing security/media/dashboard tests, then 118 Phase 13/email/history tests, 171 Phase 13/security/dashboard tests and 217 Phase 13/risk/remediation/explanation tests passed. Counts overlap and must not be summed as unique tests.
- `python scripts/security_probe.py`: local_dast.json, 16 HTTP checks covering private 401, SSRF private/metadata/numeric IP, malformed JSON, oversized request, hostile origin, SVG, CSRF, invalid bearer fallback and role restriction. Local probes complement fixture tests; they do not simulate every attack or prove production isolation.
- Real disposable linked-worker smoke: linked_worker_smoke.json, benign example.com returned PARTIAL/UNKNOWN with policy 6.2.1; no saved investigation, public attack target or secret recording. This verifies actual scanner-child startup, distinct from the local HTTP security probes.
- `python -m bandit -r app utils ml -f json`: bandit_runtime.json; broad app/utils/ml/scripts run is bandit.json with manual tool warnings retained. No security control was disabled to silence results.
- `python -m flake8 ... --select E9,F63,F7,F82`, `python -m pip check`: fatal syntax checks and installed consistency logs.
- `python -m pip_audit -r requirements-dev.txt --format cyclonedx-json --output ...`: dependency_sbom.json and dependency_audit.log. Includes declared runtime/media/email plus development requirements, not optional image-ML extras. Results describe known vulnerability data at run time.
- `python scripts/security_inventory.py`: supply_chain.json, content-free working-tree credential-format/literal checks and installed license inventory. Not Git-history gitleaks or license/legal certification.
- `python -m pip freeze`: environment_freeze.txt; reproducible snapshot of this environment, not a platform-specific production hash lock.
- `git diff --check`: whitespace verification. `docker version` failed because the Linux engine daemon is unavailable; no image/container/Linux validation claim.

Fixtures exercise roles/IDOR/BOLA/CSRF, mass assignment, duplicate/deep/non-finite JSON, SQL/XSS, DNS pinning/rebinding/private redirects, compressed/oversized retrieval, MIME/ZIP bombs/unsafe paths, upload magic/extension, process timeout/memory/CPU/output/start failure cleanup, minimal worker environment, rate/queue/capacity, safe errors/logging, export escaping and unknown/partial failure policy. A malicious provider/schema or failed decoder cannot override Phase 6 or Phase 7.

Skipped/unverified: full external scanner/penetration test, Git-history scan, Docker build/runtime, real multi-worker Redis/proxy/TLS stress, Unix worker enforcement, OS filesystem/network sandbox, dynamic browser worker, signed model artifact trust root, legal license/privacy compliance assessment and representative detection accuracy evaluation.
