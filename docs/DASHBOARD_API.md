# Dashboard API contract

Phase 12 contract version: **12.0**.

GET /api/v1/dashboard/session returns principal, CSRF token for cookie sessions and authoritative Phase 6 display policy. GET /api/v1/dashboard/summary and /api/v1/analytics/trends return descriptive tenant analytics. GET /api/v1/investigations supports verdict/severity/entity_type/status/confidence_min/since/until/q/source/evidence_type/brand/domain/limit/offset. GET /api/v1/investigations/<id> and /evidence, /timeline, /graph provide version 12.0 projections. GET /api/v1/investigations/compare?a=<id>&b=<id> labels incompatible entity types. GET /api/v1/entities/search?q=<value> performs normalized exact entity search.

GET/POST /api/v1/cases, GET/POST /api/v1/cases/<id>, POST /notes and POST /api/v1/investigations/<id>/feedback implement analyst workflows. Case mutation requires integer revision. GET /api/v1/investigations/<id>/export?format=json|html requires writer role; GET /api/v1/dashboard/audit requires ADMIN. Pagination defaults 25/max 100, offset max 2000; existing JSON limit 8 KiB remains. Date filters require timezone-qualified ISO timestamps. Cookie mutations need X-CSRF-Token or csrf_token form value; API_CLIENT uses its own bearer token. Email-job bearer tokens never grant dashboard access.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
