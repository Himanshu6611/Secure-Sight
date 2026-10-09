# Production environment and secret setup

Use `compose.production.yml` with secret files materialized by a deployment secret manager outside the repository. Never commit production values or copy a developer `.env` into an image. Only non-secret origins, hostnames, and secret-file paths are interpolated by Compose; secret values are mounted as read-only Compose secrets.

Required values:

| Variable | Requirement |
| --- | --- |
| `SECURESIGHT_IMAGE` | Registry reference pinned to `@sha256:<64 hex characters>`. Deploy a reviewed build, not `latest`. |
| `FLASK_SECRET_KEY_FILE` | Host path to a root-owned file containing an independent cryptographically random value of at least 32 characters. Compose mounts it read-only at `/run/secrets/flask_secret_key`; rotating it invalidates signed sessions. |
| `DASHBOARD_ENCRYPTION_KEY_FILE` | Host path to a root-owned file containing an independent random value of at least 32 characters. Compose mounts it read-only at `/run/secrets/dashboard_encryption_key`; preserve it with encrypted backups because loss makes encrypted records unrecoverable. |
| `SITE_URL` | The exact public HTTPS origin, for example `https://security.example.com`. |
| `TRUSTED_HOSTS` | Comma-separated explicit hostnames accepted by the application. |
| `ALLOWED_ORIGINS` | Comma-separated explicit HTTPS browser origins. |
| `RATELIMIT_STORAGE_URI_FILE` | Host path to a root-owned file containing the authenticated private shared Redis URL, preferably `rediss://`. Compose mounts it read-only at `/run/secrets/redis_url`; validate network ACLs and TLS before launch. |

Other supported application settings are listed in the repository's root `.env.example`; the following non-secret settings may be passed through the deployment's protected runtime configuration when tuning is needed:

| Variable | Purpose / default | Validation and exposure |
| --- | --- | --- |
| `LOG_LEVEL` | Log threshold; `INFO`. | Must be a known logging level. Keep production at `INFO` or above. |
| `MAX_CONCURRENT_SCANS` | Per-process scan bound; `2`. | Positive integer. The production Compose profile uses one web worker. |
| `SCAN_RATE_LIMIT`, `ACTOR_SCAN_RATE_LIMIT` | Anonymous and authenticated detector request ceilings; `20 per minute` and `10 per minute`. | Must be positive limits; shared counters require the configured Redis service. |
| `SEO_INDEXING_ENABLED` | `false`. | Boolean; enable only after canonical origin and public release review. |
| `HF_HUB_OFFLINE` | `1`. | Set by production Compose; model downloads are disabled at runtime. |
| `TESSERACT_CMD` | Optional explicit OCR executable path; empty uses system Tesseract. | Set only to a trusted local executable path; production image includes Tesseract. |
| `C2PA_TRUST_ANCHORS_FILE` | Optional operator-provisioned local C2PA trust-anchor PEM path. | Never source trust anchors from uploads; mount approved anchors read-only if enabled. |
| `WEB_CONCURRENCY` | Gunicorn workers; `1` in production. | Fixed to one for the single-host SQLite topology. |
| `PORT` | Gunicorn listen port; `5000` by default. | Container port only; expose via the configured reverse proxy. |
| `TRUSTED_PROXY_IPS` | Trusted ingress proxy addresses; empty by default. | Configure exact ingress addresses; wildcard is rejected. |
| `DASHBOARD_DB_PATH` | Persistent private dashboard SQLite path. | Fixed to `/var/lib/securesight/dashboard.sqlite3` on the named production volume. |

`SEO_INDEXING_ENABLED` defaults to `false`. Set it to `true` only after the real public origin, canonical host, redirects, and public pages have been reviewed. The deployment fixes `APP_ENV=production`, `WEB_CONCURRENCY=1`, `HF_HUB_OFFLINE=1`, and the dashboard database path. The database lives in the Compose named volume `securesight_state`.

Generate each key independently using a cryptographically secure random generator such as Python `secrets.token_urlsafe(48)`; place files in a root-owned host directory with mode `0700`. With file-backed Docker Compose secrets, the source is bind-mounted and Compose cannot remap its UID/GID, so make each file root-owned and read-only (mode `0444`) inside that protected directory, or use a secret manager that mounts readable files for UID `10001`. Do not place secret values in Compose environment output, chat, or command logs. Compose checks that secret file paths are supplied, not key randomness, origin correctness, Redis reachability, or Redis TLS validity. Validate that the service UID can read them and check those external properties through the operator's deployment platform before launch. `app.core.secrets.runtime_secret` rejects conflicting direct and file-based settings, empty or oversized files, and control characters.

The included `render.yaml` is not configured for durable dashboard state: its free service filesystem is not the Compose named volume. Do not enable dashboard persistence or use that descriptor for production investigations until a durable storage plan and the encryption-key injection are configured and verified.
