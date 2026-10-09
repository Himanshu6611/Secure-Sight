# SecureSight

React workbench with a Flask backend for URL phishing analysis, optional email classification and image forensic indicators.

The active URL model is **5.1.1**, trained with corrected PhiUSIIL labels (project target: 0 legitimate, 1 phishing), domain-disjoint splits and fold-local preprocessing. The feature schema contains **97 fields**: 59 URL, 9 domain, 22 HTML and 7 content fields. Only observed URL features are learned; domain/web observations inform a separate evidence policy. Missing observations remain unavailable.

## Run locally

Use Python 3.12 and the pinned virtual environment. Preserve existing .env secrets.

    .\venv\Scripts\python.exe -m pip install -r requirements-dev.txt
    .\venv\Scripts\python.exe -m app.app

Build the React workbench and start Flask:

    cd web
    npm ci
    npm run build
    cd ..
    .\\venv\\Scripts\\python.exe -m app.app

Open http://localhost:5000. The development server binds to loopback with debugging disabled. Provision the trusted models/v5 bundle for a fresh checkout. The production container builds the same frontend bundle during its multi-stage build. See the [React workbench architecture](docs/REACT_WORKBENCH.md) for scan contracts and validation.

## Behavior

- One shared pipeline runs URL, domain, static HTML/content and corrected ML analysis.
- Conventional www prefixes are normalized in the lexical view; network destinations are unchanged.
- Failed essential stages return **Analysis incomplete**, with null probability when inference fails.
- Phase 6 uses a centralized risk engine. **Phishing** requires sufficient confidence, coverage and independent evidence without contradictions; incomplete observations can return **Unknown**.

Phase 6 implementation and integration are tested. Risk weights and confidence are provisional; confidence is not a calibrated probability. The available development dataset lacks full HTML/domain observations, so representative verdict accuracy remains unverified. See [Phase 6 report](docs/PHASE_06_REPORT.md) and [validation scope](docs/RISK_CALIBRATION.md).

Phase 7 adds deterministic evidence-backed reasons, conflicting/missing observations and actual local URL model sensitivities to the existing API and result page. See [Phase 7 report](docs/PHASE_07_REPORT.md). Explanations describe available evidence and do not certify detection accuracy.

Phase 8 adds bounded HTTP redirect chains, static meta/JavaScript navigation indicators, final-destination analysis and privacy redaction. Scoring/explanations are versioned 6.1.0/7.1.0; the serving model/schema remains 5.1.1. Dynamic browser execution is not implemented. See [Phase 8 report](docs/PHASE_08_REPORT.md).
- **No strong phishing indicators** is not a safety guarantee.
- Historical blacklist matches are unconfirmed suspicious evidence, never a current threat feed or proof of safety.
- Dynamic browser execution is unavailable and explicitly reported. No JavaScript or forms execute.
- Unavailable optional email/image models do not produce definitive classification.

## Verification and training

    .\venv\Scripts\python.exe -m pytest -q
    .\venv\Scripts\python.exe -m pip check
    .\venv\Scripts\python.exe -m pip_audit
    # Offline training with publisher CSV in data/raw:
    .\venv\Scripts\python.exe -m ml.corrected_training

Current versioned data is data/v5_1_1. Frozen split IDs, hashes, threshold selection, fold audits and final predictions are recorded. Legacy artifacts are not used by the scan service. Joblib artifacts must come from trusted maintainers.

The historical test result is **98.53% accuracy**, **97.19% phishing recall**, **0.45% false-positive rate**, across 35,554 rows. These results do not establish live public-web performance. Prior versions used the same source benchmark; a fresh external temporal holdout is required.

## Documentation

- [Remediation and validation](docs/REMEDIATION_20261008.md)
- [Architecture](docs/ARCHITECTURE.md)
- [API](docs/API.md)
- [Security](docs/SECURITY.md)
- [Development and deployment](docs/DEVELOPMENT.md)
- [Original audit](docs/PHASE_01_05_VERIFICATION_REPORT.md)

Phase 12 adds tenant-scoped dashboard accounts, roles and encrypted investigation storage; earlier scan endpoints remain available anonymously without saving history. Public deployment remains gated on representative external testing and deployment verification.

## Phase 18 Docker deployment

Local development uses `docker-compose.yml`. Single-host production configuration is separate in `compose.production.yml` and requires externally managed secrets and Redis. See the [deployment architecture](docs/PRODUCTION_ARCHITECTURE.md), [environment setup](docs/PRODUCTION_ENVIRONMENT.md), [backup and rollback runbook](docs/BACKUP_RESTORE_ROLLBACK.md), [smoke checklist](docs/DEPLOYMENT_SMOKE_TEST.md), and [Phase 18 validation report](docs/PHASE_18_REPORT.md). Public deployment remains blocked on the unresolved high-severity image findings and deployment-owner prerequisites.

## Phase 9 brand and historical intelligence

Integrated scans expose version 9.0.0 brand evidence, bounded same-site inspection, IANA-discovered RDAP with WHOIS fallback, and separate domain/website/page age fields. Serving model inputs remain 5.1.1. Historical coverage is limited to bounded process-local observations; archive, passive DNS, certificate and ownership history are unavailable. The curated brand registry is incomplete and official matches do not whitelist safety.

See [Phase 9 verification](docs/PHASE_09_REPORT.md), [brand intelligence](docs/BRAND_INTELLIGENCE.md) and [inspection limits](docs/DEEP_WEBSITE_INSPECTION.md). Live PayPal smoke still produced a model-driven SUSPICIOUS verdict; representative accuracy validation and public-release readiness remain pending.

## Phase 10 media foundation

Multipart `POST /api/v1/media/analyze` performs bounded image intake, original/perceptual hashing, measured forensics, real OCR/multi-QR, offline C2PA verification and existing website/brand/domain/risk/explanation handoff. Install `requirements-media.txt` plus trusted Tesseract language packs. Image-only results remain UNKNOWN; evaluated deepfake models and visual logos are unavailable, with null probabilities. The old CLIP/0.5 fallback and fabricated image threat percentage were removed.

See [media API and architecture](docs/MEDIA_INTELLIGENCE.md), [security limits](docs/MEDIA_SECURITY.md) and [Phase 10 implementation status](docs/PHASE_10_REPORT.md). Phase 10 remains partial and is not a public-release accuracy guarantee.

## Phase 11 email intelligence

Install `requirements-email.txt`. Original EML/raw MIME supports bounded identity/header inspection, actual DKIM/ARC checks, contextual body/BEC indicators, attachment inspection and website/media correlation. Email exports in PDF, DOCX and XML are text-extracted in an isolated worker for body and link analysis; these exports do not preserve trusted delivery headers, so SPF/DKIM/DMARC authentication is unavailable. `POST /api/v1/email/analyze` creates an ephemeral bearer-protected job; production results use encrypted shared Redis. Uploaded authentication claims remain untrusted; actual SPF requires trusted SMTP ingress. No calibrated email model is active.

See [email architecture](docs/EMAIL_THREAT_INTELLIGENCE.md), [privacy/API](docs/EMAIL_PRIVACY.md) and [Phase 11 report](docs/PHASE_11_REPORT.md). Status remains PARTIAL and public-release accuracy validation is pending.

## Phase 12 private investigations

Open `/dashboard` for tenant-scoped investigations, evidence/graph/timeline, descriptive analytics, cases, analyst feedback and authorized exports. Operator-provisioned accounts are required. Logged-in scans are recorded; anonymous scans are not. Private records use encrypted SQLite storage. Production requires a durable `DASHBOARD_DB_PATH` and dedicated `DASHBOARD_ENCRYPTION_KEY`; the dashboard otherwise stays disabled.

See [architecture](docs/DASHBOARD_ARCHITECTURE.md), [account provisioning](docs/DASHBOARD_ACCESS_CONTROL.md), [API](docs/DASHBOARD_API.md) and [Phase 12 verification](docs/PHASE_12_REPORT.md). Keep `instance/` private and out of source control. `dashboard-purge --tenant NAME` removes private stored content; encrypted backups require separate retention management. Prior intelligence/calibration and public-release gaps remain.

## Phase 13 backend hardening

Private runtime files are excluded from Docker builds. Analysis children use minimal environments and disposable temp workspaces; API/provider JSON is bounded and rejects duplicate/non-finite values. Authenticated detector accounts/tokens have additional endpoint quotas (`ACTOR_SCAN_RATE_LIMIT`), with strict bearer precedence, safe error/log correlation and provider failure circuits. Scoring and explanation authority remain Phase 6/7.

Phase 6 policy 6.2.1 withholds LEGITIMATE for incomplete intelligence; low-risk partial results remain UNKNOWN, with unchanged risk values and historical snapshots.

See [Phase 13 verification](docs/PHASE_13_REPORT.md), [threat model](docs/THREAT_MODEL.md), [API security](docs/API_SECURITY.md), [SSRF](docs/SSRF_DEFENSE.md), [upload limits](docs/UPLOAD_SECURITY.md) and [retention](docs/DATA_RETENTION.md). Local security probes/inventory tools are in `scripts/security_probe.py` and `scripts/security_inventory.py`. OS worker isolation, container/production verification and earlier accuracy gaps remain public-release gates.
