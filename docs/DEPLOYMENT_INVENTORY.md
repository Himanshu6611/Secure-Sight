# Deployment artifact inventory

| Artifact | Purpose | Production handling |
| --- | --- | --- |
| `Dockerfile` | Multi-stage Python 3.12 image, pinned base digest and runtime packages, verified model bundle, non-root Gunicorn process. | Build in CI and deploy the reviewed immutable image digest. |
| `requirements-runtime.lock` | Exact Python runtime package versions used to construct the image. | Update and review dependency changes with the image build. |
| `.dockerignore` | Excludes local secrets/state, test material, raw/derived datasets, and unrelated model bundles from the build context. | Keep the ignore list aligned with every new `COPY` instruction. |
| `docker-compose.yml` | Loopback-only local development service. | Do not use as the production topology. |
| `compose.production.yml` | Single-host production container hardening, named state volume, required configuration, and readiness health check. | Requires external Redis, operator-provided secrets and host reverse proxy. |
| `render.yaml` | Manual ephemeral Render Docker deployment descriptor (`autoDeploy: false`). | No persistent dashboard volume; not ready for production private investigations. |
| `models/v5/` | Approved model and metadata files checked against recorded SHA-256 values at image build. | Included in the image. Do not replace individual files without updating and reviewing model metadata. |
| `data/blacklist.csv`, `data/metadata/` | Runtime blacklist and model/data provenance metadata. | Included in the image. Keep source datasets outside the production image. |
| `docs/PRODUCTION_*.md`, `docs/BACKUP_RESTORE_ROLLBACK.md`, `docs/DEPLOYMENT_SMOKE_TEST.md` | Operator configuration, architecture, release checks, and recovery guidance. | Complete the staging checklist and record release evidence before public exposure. |

The image includes the source application, runtime libraries, Tesseract OCR, the pinned `models/v5` bundle, blacklist, and metadata. Raw training corpora, derived feature tables, staging/legacy models, test fixtures, local SQLite files, and environment files are not deployment inputs.
