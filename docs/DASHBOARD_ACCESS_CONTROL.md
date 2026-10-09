# Access control and provisioning

Phase 12 contract version: **12.0**.

ADMIN and ANALYST can read/write/export within their tenant; VIEWER can read but cannot create scans/cases/notes/feedback or export; API_CLIENT has read/write/export API capability using its own random bearer token. ADMIN can read the scoped audit API. Every account sees only its explicitly provisioned shared tenant. Tenant membership is authorization to that workspace, so allocate a separate tenant for private individual investigations.

Provision with .\venv\Scripts\python.exe -m flask --app app:create_app dashboard-user --username NAME --tenant WORKSPACE --role ANALYST (password is securely prompted; minimum 12 characters). API_CLIENT provisioning shows its token once; only a keyed hash is stored. Sessions expire after one hour. dashboard-disable-user --username NAME revokes existing sessions/tokens on the next request. No self-registration, default credentials, external SSO or account administration UI is implemented. Production dashboard stays disabled unless DASHBOARD_DB_PATH and a dedicated DASHBOARD_ENCRYPTION_KEY of at least 32 characters are supplied.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
