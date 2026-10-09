# Dashboard security

Phase 12 contract version: **12.0**.

Every private API requires server-side authentication and tenant authorization, including search, graphs, comparisons, exports, notes and evidence references. Session roles are loaded from active database accounts on each request; cookie claims cannot supply roles/tenants. CSRF guards authenticated mutations including detector submissions. Cross-origin middleware, login/query rate limits, byte/row caps, no-store, noindex, CSP, nosniff and frame denial are retained.

Jinja escaping and JS textContent/createElement encode malicious titles, OCR, filenames, subjects and notes. No innerHTML, eval, unsafe links to submitted destinations, remote iframe or attachment execution action exists. HTML exports are encoded downloadable attachments with sandbox/default-src none CSP. SQLite statements bind request values; search indexes are keyed hashes. Audit events are HMAC chained, content-free and verifiable; external anchoring is needed to detect tail truncation or compromise of both DB and key. HMAC is not a WORM service.

Verification: `tests/test_phase12_dashboard.py`; [Phase 12 report](PHASE_12_REPORT.md).
