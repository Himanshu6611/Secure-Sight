# Development and deployment

Use Python 3.12 and requirements-dev.txt. Preserve existing .env. Run python -m app.app inside the virtual environment, then open http://localhost:5000. The local Flask server binds to loopback with debugger disabled.

Active bundle: models/v5/model.pkl, preprocessor.pkl, feature_schema.json, threshold.json, metrics.json, model_metadata.json. Runtime/artifacts use scikit-learn 1.5.1; mismatches fail closed. Legacy models/ensemble.pkl is not used by the URL service.

Run python -m ml.corrected_training for corrected offline training. It reads data/raw/PhiUSIIL_Phishing_URL_Dataset.csv, creates data/v5_1_1, freezes registrable-domain splits, tunes training folds, calibrates on separate domains, selects a threshold on another partition, then evaluates frozen test rows. Stop the app before publishing a new bundle and restart afterward. Allocate a new dataset version when features/provenance change.

Prepared features contain 59 observed URL columns and 38 unobserved optional columns. Optional features are not claimed as learned evidence. PhiUSIIL source 1 legitimate maps to project 0 legitimate.

Run python -m pytest -q, python -m pip check, python -m pip_audit. Tests forbid live DNS/socket traffic and stub gateways for deterministic attacks. They test www variants, fail-closed inference, corruption, private redirects, TLS checks, DOM limits, all forms and shared API capacity. Evidence: reports/remediation_20261008.

A historical source test is insufficient for launch. Obtain fresh labeled temporal/domain holdouts, representative HTML/domain snapshots, and agreed error-rate criteria before public release.

Production requires APP_ENV=production, strong FLASK_SECRET_KEY, HTTPS SITE_URL, explicit TRUSTED_HOSTS/ALLOWED_ORIGINS and reachable shared Redis RATELIMIT_STORAGE_URI. Review Redis TLS/auth and reverse-proxy client-IP trust. Untrusted forwarded headers are ignored.

Docker build validates compatible URL artifacts. A Docker daemon/build, production Redis, TLS/reverse proxy, load test and public deployment are not verified here. Flask development serving is not a production executor.

Email/image models are optional. Image heuristics cannot verify authenticity. CLIP must be pre-provisioned and separately audited; request-time downloads remain disabled. Database/auth/history are absent.
