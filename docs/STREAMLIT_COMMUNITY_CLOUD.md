# Streamlit Community Cloud deployment

SecureSight has a Streamlit entry point at `streamlit_app/main.py`. It adapts the existing Flask URL, email and image API routes in-process, so the scanners keep their input validation, shared risk policy, upload limits and isolated decoder workers. The Streamlit page does not start a second public Flask server.

## Deployment coordinates

- Repository: `Himanshu6611/Secure-Sight`
- Branch: `codex/production-readiness` until reviewed and merged
- Main file: `streamlit_app/main.py`
- Python: 3.12
- Dependency file: `streamlit_app/requirements.txt`
- System packages: root `packages.txt` (Tesseract OCR and English/Hindi data)
- Streamlit configuration: root `.streamlit/config.toml`

## Required setup

The public app intentionally fails closed until all three values are configured in Community Cloud's app secrets:

```toml
FLASK_SECRET_KEY = "<generated random value, at least 32 characters>"
RATELIMIT_STORAGE_URI = "rediss://default:<password>@<TLS Redis host>:6379"
SITE_URL = "https://<chosen-app-name>.streamlit.app"
```

Use a reachable TLS-enabled Redis provider such as Upstash for the shared rate-limit store. The Flask app checks Redis when it starts and fails closed when the service is unavailable. Do not use `memory://` or an unencrypted `redis://` for a public deployment. `.streamlit/secrets.example.toml` is a template only; never commit `.streamlit/secrets.toml` or real credentials. Configure Python 3.12 in Community Cloud's Advanced settings.

Create the app from the repository's deployment page, select the branch and `streamlit_app/main.py`, choose Python 3.12, add the secrets above, and deploy. Community Cloud reads Python dependencies from the file beside the entry point, and reads Linux packages and Streamlit configuration from the repository root. See [Streamlit's deployment guide](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy), [dependency guide](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies), and [file organization guide](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/file-organization).

## Service limits and privacy

- Uploads are capped at 2 MB for email files and 6 MB for images. Temporary decoder files are cleaned up by the existing worker. The UI does not save scans to the private dashboard.
- Email results remain in the existing bounded, in-memory job store for up to five minutes. A restart, sleep or replica change can lose an in-flight result; users may need to submit the file again.
- Community Cloud is a shared, resource-limited hosting service. It is suitable for a reviewed public demo, not a production availability or capacity guarantee. Streamlit describes approximate resource bounds that can change; test real traffic and memory usage before relying on it.
- Uploaded content is processed by the hosted app. A public demo should warn users not to submit confidential messages or images. This deployment does not promise durable storage, private tenant accounts, a production worker sandbox, or cross-user campaign analysis.
- Image AI/deepfake origin and email legitimacy are not guaranteed. The interface must preserve `UNKNOWN`/incomplete outcomes and describe observed evidence rather than claiming certainty.
- The engineering gate currently passes, but the release profile is blocked by 11 critical/high Docker Scout findings for the Docker artifact and seven missing production-evidence gates. The hosted Streamlit runtime has not had a separate vendor-image scan, so changing hosting paths does not clear the release blockers or certify the service as production-ready. Keep deployment private/review-only until the remaining security and evidence gates are resolved.

## Local checks

Install the same deployment dependency set and system OCR tools, then run:

```bash
python -m pip install -r streamlit_app/requirements.txt
streamlit run streamlit_app/main.py
python -m pytest tests/test_streamlit_deployment.py -q
```

Without the production secrets, the app should show setup guidance and stop before initializing a public scanner. With secrets, the three upload/scan tabs are available.
