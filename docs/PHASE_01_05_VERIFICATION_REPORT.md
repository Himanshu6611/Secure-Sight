# SecureSight Phase 1–5 Verification Report

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Executive Summary

**MAJOR REWORK REQUIRED. Do not start Phase 6.** Audit performed on 8 October 2026 against the current uncommitted working tree in `D:\capstone Project`, using the user's complete Phase 1–5 verification specification. Implementation files were not modified. SHA-256 comparison confirms all 89 snapshotted source, test, configuration and deployment files are unchanged. Only this report and independent evidence under `reports/verification_20261008/` were created.

The architecture foundation and much of lexical/static analysis exist. However, two critical findings invalidate production readiness: the primary dataset's class semantics are reversed, and the later TLS/fetch paths can attempt private-network connections. The main scan does not call the Phase 5 model. Its advanced intelligence is displayed but does not affect its final decision. Training fills 46 of 57 canonical features with constants from an old 11-feature dataset, while live feature aggregation silently loses important values.

**Results:** End-to-End FAIL; Security FAIL; ML Integrity FAIL; Test Integrity FAIL. Final historical test-set integrity is **CANNOT VERIFY**, not a claim that historical test tuning was proven. Current training code keeps its outer test partition away from tuning, but the saved artifact/report does not reproduce that partition and no immutable split/run history establishes how it was trained.

Original environment: pytest aborted with two collection errors because `bs4` was missing. The declared `beautifulsoup4==4.12.3` was supplied with pip `--target` in an isolated evidence folder; no project requirements or installed environment packages were changed. With this dependency supplied, the actual project suite ran **180 tests: 179 passed, 1 failed, 0 skipped, 0 collection errors**, with 28 warnings. A separate broad discovery run also collected vendored dependency tests; those results are explicitly excluded from project totals.

Finding counts: **2 critical, 8 high, 7 medium, 3 low**. Findings are consolidated root causes, not counts of every affected endpoint or every Bandit warning. Scores assess actual implementation rather than the percentage of test cases passing.

## Repository Overview

| Area | Actual repository implementation |
|---|---|
| Frontend | Flask/Jinja templates in `app/templates`, HTML/CSS/JavaScript in `app/static`; Bootstrap/CDN dependencies; server-rendered form results |
| Backend | Python 3.12, Flask application factory `app/__init__.py`; entry point `app/app.py`; routes and shared scan service |
| API | Blueprint `app/api/v1.py`, `/api/v1/scan`, URL/domain/web/ML endpoints, `/api/analyze` compatibility alias, health/readiness |
| ML | Legacy joblib URL/email models in `utils/model.py`; separate `ml/` training/calibration/stacking/inference package; versioned `models/v5/` |
| Features | Legacy 11 URL features; 50 advanced URL features; Phase 3 domain features; static HTML and keyword features |
| Dataset | Raw PhiUSIIL CSV, `data/cleaned.csv`, legacy `data/features.parquet`, metadata JSON; preprocessing scripts |
| Database | No relational/document database, ORM, database migrations or persistent scan history found; files and an in-process TTL cache |
| Security | `app/security/urls.py`, pinned legacy outbound gateway, middleware, shared Flask-Limiter rate policy, headers and input limits; later fetch/TLS modules bypass the gateway |
| Authentication / authorization | No user login, sessions with identities, roles or access policy; public scanner; no public training endpoint |
| Configuration | `.env.example`, python-dotenv, centralized `app/core/config.py`; development memory limiter, production requires Redis and explicit secure settings |
| Dependencies | `requirements.txt`, `requirements-dev.txt`, optional `requirements-image-ml.txt`; existing Windows venv; scientific Python + requests/bs4/tldextract/whois |
| Testing | pytest under `tests/`; deterministic HTML/ML fixtures; autouse network blocking partially mocks network behavior |
| Deployment | Dockerfile, compose and Gunicorn configuration; compose parses, Docker daemon unavailable; no container runtime/build verification |
| Documentation | README, root phase reports, `docs/` architecture/security/API/ML reports; multiple claims conflict with implementation |
| SEO | Canonical, description, OpenGraph/Twitter tags, JSON-LD, robots and sitemap routes exist; no search-engine indexing/live deployment verified |

### Audit evidence and reproducibility

- `pytest.xml`: unmodified environment's collection failure.
- `pytest_project.xml` and `pytest_project.log`: project-only suite with isolated parser dependency.
- `pytest_isolated.xml/log`: broad discovery contaminated by dependency package tests; not used for project totals.
- `runtime_audit.py`, `runtime_results.json`: independent feature, cache, inference, seven API end-to-end cases, current split and saved-model evaluation.
- `additional_audit.py`, `additional_results.json`: source-label reconciliation, socket traps for SSRF, deadline test, explicit failure simulation, artifact inspection and memory.
- `api_failure_audit.py`, `api_failure_results.json`: forced feature/model failures, error sanitization, empty feature API response and exhausted scan semaphore checks.
- `dependency_audit.json`, `installed_dependency_audit.json`, `outdated.json`, `bandit.json`, `lint.log`, `source_hashes_before.json`.

Run evidence scripts with `venv\Scripts\python.exe`. Project suite reproduction: set `PYTHONPATH` to the absolute `reports\verification_20261008\audit_dependencies` directory, then run `python -m pytest tests -q`. The audit scripts use fake transport and socket traps; they never retrieve a live phishing page or send a packet to a private target. Network-dependent external availability and production deployment remain unverified. Mock timings are not public-network service benchmarks.

## Phase 1 Verification

The foundation has useful separation, centralized request policy and strong legacy URL validation. Its security assumptions no longer hold for the added Phase 3/4 network clients. A syntactically public hostname is insufficient when the connection can resolve to a private address later.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| Existing architecture documented | ✅ VERIFIED | Source traced through app factory, blueprints, service, security, utils and ml modules; route tests execute these paths. |
| Frontend/backend separation | ✅ VERIFIED | Source traced through app factory, blueprints, service, security, utils and ml modules; route tests execute these paths. |
| Organized API | ✅ VERIFIED | Source traced through app factory, blueprints, service, security, utils and ml modules; route tests execute these paths. |
| Modular ML layer | ✅ VERIFIED | Source traced through app factory, blueprints, service, security, utils and ml modules; route tests execute these paths. |
| Separated services | ✅ VERIFIED | Source traced through app factory, blueprints, service, security, utils and ml modules; route tests execute these paths. |
| Centralized configuration | ✅ VERIFIED | Source traced through app factory, blueprints, service, security, utils and ml modules; route tests execute these paths. |
| Environment variables | ✅ VERIFIED | Production configuration rejects weak/absent secrets; git tracks .env.example and not .env; config uses environment variables. No real credential found in reviewed implementation. This is not a proof of clean historical Git secrets. |
| Secrets not hard-coded | ✅ VERIFIED | Production configuration rejects weak/absent secrets; git tracks .env.example and not .env; config uses environment variables. No real credential found in reviewed implementation. This is not a proof of clean historical Git secrets. |
| .env excluded from Git | ✅ VERIFIED | Production configuration rejects weak/absent secrets; git tracks .env.example and not .env; config uses environment variables. No real credential found in reviewed implementation. This is not a proof of clean historical Git secrets. |
| .env.example | ✅ VERIFIED | Production configuration rejects weak/absent secrets; git tracks .env.example and not .env; config uses environment variables. No real credential found in reviewed implementation. This is not a proof of clean historical Git secrets. |
| Centralized errors | ⚠️ PARTIALLY IMPLEMENTED | Generic central handler is tested, but later ML and intelligence paths expose exception details; M2. |
| Safe error responses | ⚠️ PARTIALLY IMPLEMENTED | Generic central handler is tested, but later ML and intelligence paths expose exception details; M2. |
| Structured logging | ✅ VERIFIED | Structured JSON events and request IDs observed during actual test-client calls; health returned 200; blueprint /api/v1 routes. |
| Request/correlation IDs | ✅ VERIFIED | Structured JSON events and request IDs observed during actual test-client calls; health returned 200; blueprint /api/v1 routes. |
| API versioning | ✅ VERIFIED | Structured JSON events and request IDs observed during actual test-client calls; health returned 200; blueprint /api/v1 routes. |
| Health endpoint | ✅ VERIFIED | Structured JSON events and request IDs observed during actual test-client calls; health returned 200; blueprint /api/v1 routes. |
| Clean dependency management | 🐛 IMPLEMENTED BUT BROKEN | Declared bs4 missing in installed environment; versioned legacy estimators warn on sklearn mismatch; M1/M7. |
| Input validation | ✅ VERIFIED | Passing security tests exercise malformed URLs, schemes, credentials, private literal addresses, size limits, allowed/disallowed origins and nonce-based headers. Production HSTS runtime test is broken; production source alone is not runtime confirmation. |
| URL validation | ✅ VERIFIED | Passing security tests exercise malformed URLs, schemes, credentials, private literal addresses, size limits, allowed/disallowed origins and nonce-based headers. Production HSTS runtime test is broken; production source alone is not runtime confirmation. |
| Request size limits | ✅ VERIFIED | Passing security tests exercise malformed URLs, schemes, credentials, private literal addresses, size limits, allowed/disallowed origins and nonce-based headers. Production HSTS runtime test is broken; production source alone is not runtime confirmation. |
| CORS configuration | ✅ VERIFIED | Passing security tests exercise malformed URLs, schemes, credentials, private literal addresses, size limits, allowed/disallowed origins and nonce-based headers. Production HSTS runtime test is broken; production source alone is not runtime confirmation. |
| Security headers | ✅ VERIFIED | Passing security tests exercise malformed URLs, schemes, credentials, private literal addresses, size limits, allowed/disallowed origins and nonce-based headers. Production HSTS runtime test is broken; production source alone is not runtime confirmation. |
| SSRF protection | 🐛 IMPLEMENTED BUT BROKEN | Legacy outbound gateway is pinned and tested; later TLS ignores unsafe DNS and fetch connects by hostname. Independent socket trap captured 127.0.0.1 connection attempts; C2. |
| Localhost/private IP blocking | 🐛 IMPLEMENTED BUT BROKEN | Legacy outbound gateway is pinned and tested; later TLS ignores unsafe DNS and fetch connects by hostname. Independent socket trap captured 127.0.0.1 connection attempts; C2. |
| Cloud metadata protection | 🐛 IMPLEMENTED BUT BROKEN | Legacy outbound gateway is pinned and tested; later TLS ignores unsafe DNS and fetch connects by hostname. Independent socket trap captured 127.0.0.1 connection attempts; C2. |
| DNS rebinding protection | 🐛 IMPLEMENTED BUT BROKEN | Legacy outbound gateway is pinned and tested; later TLS ignores unsafe DNS and fetch connects by hostname. Independent socket trap captured 127.0.0.1 connection attempts; C2. |
| Timeout limits | ⚠️ PARTIALLY IMPLEMENTED | Legacy bounded resolver/network timeouts; Phase 3 getaddrinfo has no enforced deadline and Phase 4 timeout is inactivity rather than total; H7. |
| Rate limiting | ⚠️ PARTIALLY IMPLEMENTED | Shared POST limits tested; new heavy endpoints lack scan semaphore. Real distributed Redis availability/worker behavior unverified; H7. |
| Authentication | ❌ NOT IMPLEMENTED | Public scanner has no identity/role layer. No public train/admin mutation endpoint found, so absence alone is not scored as an unauthorized administrative access vulnerability. |
| Authorization | ❌ NOT IMPLEMENTED | Public scanner has no identity/role layer. No public train/admin mutation endpoint found, so absence alone is not scored as an unauthorized administrative access vulnerability. |
| Dependency security | ✅ VERIFIED | Both installed-environment and requirements-resolved pip-audit completed with zero known vulnerabilities on this audit date; this does not establish application security. |
| Git secret hygiene | ⚠️ PARTIALLY IMPLEMENTED | Current .env exclusion and explicit production secrets verified; complete historical credential scan and remote repository exposure cannot be established. |

| Requirement | Status | Evidence / limitation |
|---|---|---|
| docs/PROJECT_AUDIT.md | ❌ NOT IMPLEMENTED | Requested docs path absent; check root reports separately. |
| docs/ARCHITECTURE.md | ⚠️ PARTIALLY IMPLEMENTED | Exists, but completion/integration claims require the corrections described below. |
| docs/SECURITY_AUDIT.md | ❌ NOT IMPLEMENTED | Requested docs path absent; check root reports separately. |
| docs/IMPLEMENTATION_STATUS.md | ❌ NOT IMPLEMENTED | Requested docs path absent; check root reports separately. |
| docs/TECH_STACK.md | ⚠️ PARTIALLY IMPLEMENTED | Exists, but completion/integration claims require the corrections described below. |
| docs/SECURITY.md | ⚠️ PARTIALLY IMPLEMENTED | Exists, but completion/integration claims require the corrections described below. |
| docs/API.md | ⚠️ PARTIALLY IMPLEMENTED | Exists, but completion/integration claims require the corrections described below. |
| docs/DEVELOPMENT.md | ⚠️ PARTIALLY IMPLEMENTED | Exists, but completion/integration claims require the corrections described below. |
| docs/PHASE_01_REPORT.md | ❌ NOT IMPLEMENTED | Requested docs path absent; check root reports separately. |

## Phase 2 Verification

The pipeline normalizes the API input, parses with urllib/tldextract, computes numerical lexical/statistical/structural features and generates heuristic indicators. Independent extraction returns **50** features. It does not expose its own schema version, validate a formal vector, or provide the full feature inventory requested. The API rejects ports other than 80/443; raw extraction can inspect arbitrary ports, so endpoint behavior is more restrictive than the extractor.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| HTTP | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| HTTPS | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| Query strings | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| Fragments | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| Percent-encoded URLs | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| Malformed URLs | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| Credentials/auth-like authority handled safely | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| IPv4 | ✅ VERIFIED | Source parsing plus passing URL/security tests; malformed/unsafe inputs rejected before analysis; fragments retained with has_fragment flag. |
| Ports | ⚠️ PARTIALLY IMPLEMENTED | Extractor has port indicators; API deliberately permits only 80/443; other suspicious ports cannot reach the feature endpoint. |
| Unicode | ⚠️ PARTIALLY IMPLEMENTED | Input host normalizes to IDNA, but original Unicode evidence is lost and no explicit Unicode/punycode feature exists. |
| Punycode | ⚠️ PARTIALLY IMPLEMENTED | Input host normalizes to IDNA, but original Unicode evidence is lost and no explicit Unicode/punycode feature exists. |
| IPv6 | 🐛 IMPLEMENTED BUT BROKEN | URL security validator supports public IPv6, but advanced has_ip is 0 for https://[2606:4700:4700::1111]/. |
| URL length | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Hostname length | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Path length | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Query length | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Digit count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Letter count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Special character count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Hyphen count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Underscore count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Dot count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Slash count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Question mark count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Ampersand count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Equals count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Percent count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| At-sign count | ✅ VERIFIED | Real returned keys: url_len, hostname_len, path_len, query_len, digit_count, letter_count, special_char_count and corresponding *_count keys; numerical tests execute extractor. |
| Fragment length | ❌ NOT IMPLEMENTED | No corresponding returned feature. |
| Colon count | ❌ NOT IMPLEMENTED | No corresponding returned feature. |
| Entropy | ✅ VERIFIED | url_entropy/domain_entropy/path_entropy, digit_ratio, special_ratio; real extraction and numerical assertions. |
| Numeric ratio | ✅ VERIFIED | url_entropy/domain_entropy/path_entropy, digit_ratio, special_ratio; real extraction and numerical assertions. |
| Special-character ratio | ✅ VERIFIED | url_entropy/domain_entropy/path_entropy, digit_ratio, special_ratio; real extraction and numerical assertions. |
| Character diversity | ❌ NOT IMPLEMENTED | No requested statistical feature; suspicious keyword count and query parameter count are not generic token statistics. |
| Token count | ❌ NOT IMPLEMENTED | No requested statistical feature; suspicious keyword count and query parameter count are not generic token statistics. |
| Average token length | ❌ NOT IMPLEMENTED | No requested statistical feature; suspicious keyword count and query parameter count are not generic token statistics. |
| Maximum token length | ❌ NOT IMPLEMENTED | No requested statistical feature; suspicious keyword count and query parameter count are not generic token statistics. |
| Encoded ratio | ❌ NOT IMPLEMENTED | No requested statistical feature; suspicious keyword count and query parameter count are not generic token statistics. |
| IP-based hostname indicator | ⚠️ PARTIALLY IMPLEMENTED | IPv4 flag implemented; IPv6 flag misses public literals. |
| Suspicious tokens | ⚠️ PARTIALLY IMPLEMENTED | Heuristic code and tests exist. API cannot analyze arbitrary ports; is_suspicious_tld searches whole URL, and brand/at-sign evidence lacks context; indicator totals do not drive final scan decision. |
| Subdomain complexity | ⚠️ PARTIALLY IMPLEMENTED | Heuristic code and tests exist. API cannot analyze arbitrary ports; is_suspicious_tld searches whole URL, and brand/at-sign evidence lacks context; indicator totals do not drive final scan decision. |
| URL shorteners | ⚠️ PARTIALLY IMPLEMENTED | Heuristic code and tests exist. API cannot analyze arbitrary ports; is_suspicious_tld searches whole URL, and brand/at-sign evidence lacks context; indicator totals do not drive final scan decision. |
| Suspicious ports | ⚠️ PARTIALLY IMPLEMENTED | Heuristic code and tests exist. API cannot analyze arbitrary ports; is_suspicious_tld searches whole URL, and brand/at-sign evidence lacks context; indicator totals do not drive final scan decision. |
| Encoding | ⚠️ PARTIALLY IMPLEMENTED | Heuristic code and tests exist. API cannot analyze arbitrary ports; is_suspicious_tld searches whole URL, and brand/at-sign evidence lacks context; indicator totals do not drive final scan decision. |
| Brand tokens | ⚠️ PARTIALLY IMPLEMENTED | Heuristic code and tests exist. API cannot analyze arbitrary ports; is_suspicious_tld searches whole URL, and brand/at-sign evidence lacks context; indicator totals do not drive final scan decision. |
| Typosquatting similarity | ⚠️ PARTIALLY IMPLEMENTED | Heuristic code and tests exist. API cannot analyze arbitrary ports; is_suspicious_tld searches whole URL, and brand/at-sign evidence lacks context; indicator totals do not drive final scan decision. |
| Punycode indicator | ❌ NOT IMPLEMENTED | No dedicated lexical feature/indicator despite IDNA input support. |
| Unicode indicator | ❌ NOT IMPLEMENTED | No dedicated lexical feature/indicator despite IDNA input support. |
| Explainable indicator | ⚠️ PARTIALLY IMPLEMENTED | Indicators have code/category/severity/description/weight; evidence not fully linked to feature values. |
| Severity | ⚠️ PARTIALLY IMPLEMENTED | Indicators have code/category/severity/description/weight; evidence not fully linked to feature values. |
| Reason | ⚠️ PARTIALLY IMPLEMENTED | Indicators have code/category/severity/description/weight; evidence not fully linked to feature values. |
| Indicator feature | ❌ NOT IMPLEMENTED | Phase 2 indicator schema does not consistently include feature and value fields. |
| Indicator value | ❌ NOT IMPLEMENTED | Phase 2 indicator schema does not consistently include feature and value fields. |
| Deterministic feature ordering | ✅ VERIFIED | Dict literal insertion order stable; repeated extractor/schema tests. JSON transport sorts keys, so consumers must not infer model ordering from API object order. |
| Stable schema | ⚠️ PARTIALLY IMPLEMENTED | Fixed literal keys and basic numeric values, but no separate contract validation and incompatible names at Phase 5 boundary; H2. |
| Missing-value handling | ⚠️ PARTIALLY IMPLEMENTED | Fixed literal keys and basic numeric values, but no separate contract validation and incompatible names at Phase 5 boundary; H2. |
| Feature validation | ⚠️ PARTIALLY IMPLEMENTED | Fixed literal keys and basic numeric values, but no separate contract validation and incompatible names at Phase 5 boundary; H2. |
| Feature version | ❌ NOT IMPLEMENTED | Advanced URL endpoint/extractor does not return a feature version. |
| URL treated as untrusted | ✅ VERIFIED | Endpoint uses strict validator; extraction is pure parsing/heuristics; no execution of URL contents. |
| No remote content execution | ✅ VERIFIED | Endpoint uses strict validator; extraction is pure parsing/heuristics; no execution of URL contents. |
| Dangerous schemes rejected | ✅ VERIFIED | Endpoint uses strict validator; extraction is pure parsing/heuristics; no execution of URL contents. |
| SSRF cannot be bypassed | ⚠️ PARTIALLY IMPLEMENTED | Lexical endpoint does not fetch; full scan invokes unsafe later network paths, C2. |

Actual Phase 2 feature dictionary:

`ampersand_count`, `at_count`, `base64_strings_count`, `brand_in_path`, `brand_in_subdomain`, `consecutive_hyphens`, `digit_count`, `digit_ratio`, `domain_entropy`, `dot_count`, `double_slash_in_path`, `equal_count`, `has_at_symbol`, `has_fragment`, `has_ip`, `has_port`, `has_scheme`, `hex_encoding_count`, `hostname_len`, `hyphen_count`, `is_https`, `is_non_standard_port`, `is_shortener`, `is_suspicious_tld`, `is_typosquatting`, `letter_count`, `letter_ratio`, `min_brand_distance`, `path_depth`, `path_entropy`, `path_len`, `percent_count`, `query_len`, `query_params_count`, `question_count`, `slash_count`, `special_char_count`, `special_ratio`, `subdomain_depth`, `subdomain_len`, `suspicious_keyword_count`, `suspicious_kw_domain_count`, `suspicious_kw_path_count`, `tilde_count`, `tld_len`, `underscore_count`, `uppercase_count`, `uppercase_ratio`, `url_entropy`, `url_len`.

## Phase 3 Verification

Domain intelligence supplies structured DNS/TLS/registration/reputation output and a versioned domain feature dictionary. DNS checks and TLS checks are disconnected: TLS runs even if resolved addresses are non-public. The cache key includes hostname only and can return HTTP intelligence for an HTTPS request. External reputation support is a skeleton that falsely reports clean when configured.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| Public-suffix-aware registrable domain | ✅ VERIFIED | Offline bundled tldextract suffix list and passing domain extraction tests; real extractor used in dataset regrouping. |
| Lowercase normalization | ✅ VERIFIED | Offline bundled tldextract suffix list and passing domain extraction tests; real extractor used in dataset regrouping. |
| Trailing-dot handling | ✅ VERIFIED | Offline bundled tldextract suffix list and passing domain extraction tests; real extractor used in dataset regrouping. |
| Subdomain handling | ✅ VERIFIED | Offline bundled tldextract suffix list and passing domain extraction tests; real extractor used in dataset regrouping. |
| IDN/Punycode normalization | ⚠️ PARTIALLY IMPLEMENTED | IDNA host conversion implemented; original IDN indicator can be lost after API normalization; UnicodeError silently passed. |
| DNS A | ✅ VERIFIED | getaddrinfo aggregation records IPv4/IPv6 results; passing fixtures and independent resolver stub. |
| DNS AAAA | ✅ VERIFIED | getaddrinfo aggregation records IPv4/IPv6 results; passing fixtures and independent resolver stub. |
| DNS CNAME | ❌ NOT IMPLEMENTED | No explicit record queries; Phase 5 invents MX/NS proxies rather than retrieving these records. |
| DNS MX | ❌ NOT IMPLEMENTED | No explicit record queries; Phase 5 invents MX/NS proxies rather than retrieving these records. |
| DNS NS | ❌ NOT IMPLEMENTED | No explicit record queries; Phase 5 invents MX/NS proxies rather than retrieving these records. |
| DNS timeouts | 🐛 IMPLEMENTED BUT BROKEN | socket.setdefaulttimeout changes global default but does not bound getaddrinfo. 1 ms configured timeout took 50.35 ms with a controlled slow resolver and returned SUCCESS; H7. |
| DNS failure states | ⚠️ PARTIALLY IMPLEMENTED | DOMAIN_NOT_FOUND, DNS_TIMEOUT, DNS_PROVIDER_ERROR exist; fetch maps all preflight failures to SSRF_BLOCKED, losing DNS distinction. |
| Safe resolution | 🐛 IMPLEMENTED BUT BROKEN | No pinned address handoff from DNS to TLS/fetch; C2. |
| DNS rebinding | 🐛 IMPLEMENTED BUT BROKEN | No pinned address handoff from DNS to TLS/fetch; C2. |
| Private IP detection | ✅ VERIFIED | ipaddress classification and fixture tests detect basic restricted addresses; detection is not enforcement at connection time. |
| Loopback detection | ✅ VERIFIED | ipaddress classification and fixture tests detect basic restricted addresses; detection is not enforcement at connection time. |
| Invalid IP detection | ✅ VERIFIED | ipaddress classification and fixture tests detect basic restricted addresses; detection is not enforcement at connection time. |
| Link-local detection | ⚠️ PARTIALLY IMPLEMENTED | Non-public addresses blocked by boolean policy, but classifier checks is_private before is_link_local and can label link-local addresses PRIVATE. |
| TLS certificate presence | ⚠️ PARTIALLY IMPLEMENTED | CERT_REQUIRED and hostname verification plus certificate date/issuer/subject parsing exist; socket failure tests and static review; real public TLS certificate retrieval was not performed, and transport remains unsafe. |
| TLS certificate validity | ⚠️ PARTIALLY IMPLEMENTED | CERT_REQUIRED and hostname verification plus certificate date/issuer/subject parsing exist; socket failure tests and static review; real public TLS certificate retrieval was not performed, and transport remains unsafe. |
| TLS expiry | ⚠️ PARTIALLY IMPLEMENTED | CERT_REQUIRED and hostname verification plus certificate date/issuer/subject parsing exist; socket failure tests and static review; real public TLS certificate retrieval was not performed, and transport remains unsafe. |
| TLS issuer | ⚠️ PARTIALLY IMPLEMENTED | CERT_REQUIRED and hostname verification plus certificate date/issuer/subject parsing exist; socket failure tests and static review; real public TLS certificate retrieval was not performed, and transport remains unsafe. |
| TLS subject | ⚠️ PARTIALLY IMPLEMENTED | CERT_REQUIRED and hostname verification plus certificate date/issuer/subject parsing exist; socket failure tests and static review; real public TLS certificate retrieval was not performed, and transport remains unsafe. |
| TLS expiry duration | ⚠️ PARTIALLY IMPLEMENTED | CERT_REQUIRED and hostname verification plus certificate date/issuer/subject parsing exist; socket failure tests and static review; real public TLS certificate retrieval was not performed, and transport remains unsafe. |
| TLS SAN | ❌ NOT IMPLEMENTED | No explicit subjectAltName extraction returned. |
| HTTPS does not automatically mean SAFE | ⚠️ PARTIALLY IMPLEMENTED | TLS itself distinguishes VALID/INVALID/UNAVAILABLE. Final scan can still say Legitimate despite failed intelligence and local reputation absence becomes SAFE; H3/H6. |
| Registration handling | ⚠️ PARTIALLY IMPLEMENTED | Safe legacy WHOIS transport reused, date parsing and age features tested; live registry availability unverified. |
| Domain age calculation | ⚠️ PARTIALLY IMPLEMENTED | Safe legacy WHOIS transport reused, date parsing and age features tested; live registry availability unverified. |
| Unavailable registration handling | ✅ VERIFIED | Controlled unavailable WHOIS gives UNAVAILABLE; recent registration produces a weighted indicator, not an automatic phishing decision. |
| Young domain not automatically phishing | ✅ VERIFIED | Controlled unavailable WHOIS gives UNAVAILABLE; recent registration produces a weighted indicator, not an automatic phishing decision. |
| Reputation provider abstraction | ✅ VERIFIED | ABC/aggregator and mock-provider tests; provider entries preserve source and ISO checked_at; actual default enables only local blacklist. |
| Multiple-provider support | ✅ VERIFIED | ABC/aggregator and mock-provider tests; provider entries preserve source and ISO checked_at; actual default enables only local blacklist. |
| Provenance | ✅ VERIFIED | ABC/aggregator and mock-provider tests; provider entries preserve source and ISO checked_at; actual default enables only local blacklist. |
| Timestamp | ✅ VERIFIED | ABC/aggregator and mock-provider tests; provider entries preserve source and ISO checked_at; actual default enables only local blacklist. |
| SAFE | ⚠️ PARTIALLY IMPLEMENTED | Declared provider states present; all-error aggregation becomes UNAVAILABLE; absence from blacklist becomes SAFE and configured external skeleton fabricates SAFE; H6. |
| SUSPICIOUS | ⚠️ PARTIALLY IMPLEMENTED | Declared provider states present; all-error aggregation becomes UNAVAILABLE; absence from blacklist becomes SAFE and configured external skeleton fabricates SAFE; H6. |
| MALICIOUS | ⚠️ PARTIALLY IMPLEMENTED | Declared provider states present; all-error aggregation becomes UNAVAILABLE; absence from blacklist becomes SAFE and configured external skeleton fabricates SAFE; H6. |
| UNKNOWN | ⚠️ PARTIALLY IMPLEMENTED | Declared provider states present; all-error aggregation becomes UNAVAILABLE; absence from blacklist becomes SAFE and configured external skeleton fabricates SAFE; H6. |
| UNAVAILABLE | ⚠️ PARTIALLY IMPLEMENTED | Declared provider states present; all-error aggregation becomes UNAVAILABLE; absence from blacklist becomes SAFE and configured external skeleton fabricates SAFE; H6. |
| ERROR | ⚠️ PARTIALLY IMPLEMENTED | Declared provider states present; all-error aggregation becomes UNAVAILABLE; absence from blacklist becomes SAFE and configured external skeleton fabricates SAFE; H6. |
| Provider timeout | ❌ NOT IMPLEMENTED | External provider performs no lookup; timeout exception clause is unreachable without network implementation. |
| Retry strategy | ❌ NOT IMPLEMENTED | No implemented retry/circuit policy. |
| Circuit breaker | ❌ NOT IMPLEMENTED | No implemented retry/circuit policy. |
| Caching | 🐛 IMPLEMENTED BUT BROKEN | TTL cache exists, but hostname-only key collides across scheme/port and dictionary has no bounded size/sweeper; M3. |
| API key protection | ⚠️ PARTIALLY IMPLEMENTED | Keys sourced from environment and not returned; real provider operation not implemented or validated. |
| Provider failure must not become SAFE | ⚠️ PARTIALLY IMPLEMENTED | All-error mock returns UNAVAILABLE, verified. With another local non-hit, aggregation can return SAFE; configured placeholder returns SAFE without evidence. |

## Phase 4 Verification

Static BeautifulSoup parsing, forms, scripts, iframes, selected external resources, keywords and brand-title mismatch are implemented. No untrusted JavaScript is executed. The so-called dynamic mode is metadata simulation, not an isolated browser. Fetch preflight checks are vulnerable to DNS rebinding, processing deadlines/resource limits are incomplete, and parser failure is not converted into a stage-specific state.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| Only HTTP/HTTPS | ⚠️ PARTIALLY IMPLEMENTED | Initial URL scheme checked; redirect destination receives DNS preflight but not full strict URL/scheme/credential validation. |
| SSRF protection | 🐛 IMPLEMENTED BUT BROKEN | Preflight safety flag not bound to actual requests socket; private socket attempt captured with zero packets sent; C2. |
| DNS/IP validation | 🐛 IMPLEMENTED BUT BROKEN | Preflight safety flag not bound to actual requests socket; private socket attempt captured with zero packets sent; C2. |
| Redirect limit | ✅ VERIFIED | Actual fetch loop stops at >3; controlled redirect chain returns REDIRECT_LIMIT_EXCEEDED. |
| Redirect revalidation | ⚠️ PARTIALLY IMPLEMENTED | DNS check per hop exists; scheme/credentials/port strict validator not reapplied and no pinning. |
| Timeout | ⚠️ PARTIALLY IMPLEMENTED | requests timeout and TIMEOUT state exercised; no total deadline and DNS preflight unbounded. |
| Response-size limit | ✅ VERIFIED | Decoded stream cap 1 MiB; independent oversized response returns RESOURCE_LIMIT_EXCEEDED. |
| Resource-count limit | ❌ NOT IMPLEMENTED | No enforced static DOM or resource-count cap; unused dynamic constants do not enforce limits. |
| DOM-node limit | ❌ NOT IMPLEMENTED | No enforced static DOM or resource-count cap; unused dynamic constants do not enforce limits. |
| Content-type validation | ⚠️ PARTIALLY IMPLEMENTED | PDF fixture rejected; missing Content-Type accepted, text/plain accepted; 404/500 accepted as SUCCESS; M4. |
| TLS verification | ⚠️ PARTIALLY IMPLEMENTED | requests verify=True observed and TLS_FAILED branch exists; live cert chain was not independently checked. |
| Safe failure states | ⚠️ PARTIALLY IMPLEMENTED | Some explicit states exist but DNS errors are conflated, parser exception escapes, and overall scan can return Legitimate despite failure. |
| INVALID_URL | ✅ VERIFIED | Actual functions emit these states, tested or independently forced; no SAFE value from fetcher itself. |
| FETCH_FAILED | ✅ VERIFIED | Actual functions emit these states, tested or independently forced; no SAFE value from fetcher itself. |
| TLS_FAILED | ✅ VERIFIED | Actual functions emit these states, tested or independently forced; no SAFE value from fetcher itself. |
| TIMEOUT | ✅ VERIFIED | Actual functions emit these states, tested or independently forced; no SAFE value from fetcher itself. |
| CONTENT_TYPE_UNSUPPORTED | ✅ VERIFIED | Actual functions emit these states, tested or independently forced; no SAFE value from fetcher itself. |
| DNS_FAILED | ❌ NOT IMPLEMENTED | These exact stage states are not implemented; DNS maps to SSRF_BLOCKED, successful fetch uses SUCCESS; central API exceptions use generic INTERNAL_ERROR. |
| HTML_PARSE_FAILED | ❌ NOT IMPLEMENTED | These exact stage states are not implemented; DNS maps to SSRF_BLOCKED, successful fetch uses SUCCESS; central API exceptions use generic INTERNAL_ERROR. |
| ANALYSIS_FAILED | ❌ NOT IMPLEMENTED | These exact stage states are not implemented; DNS maps to SSRF_BLOCKED, successful fetch uses SUCCESS; central API exceptions use generic INTERNAL_ERROR. |
| ANALYZED | ❌ NOT IMPLEMENTED | These exact stage states are not implemented; DNS maps to SSRF_BLOCKED, successful fetch uses SUCCESS; central API exceptions use generic INTERNAL_ERROR. |
| REDIRECT_LIMIT | ⚠️ PARTIALLY IMPLEMENTED | Equivalent implemented names REDIRECT_LIMIT_EXCEEDED / RESOURCE_LIMIT_EXCEEDED; consumers must use actual names. |
| RESOURCE_LIMIT | ⚠️ PARTIALLY IMPLEMENTED | Equivalent implemented names REDIRECT_LIMIT_EXCEEDED / RESOURCE_LIMIT_EXCEEDED; consumers must use actual names. |
| Fetch failure must not become SAFE | 🐛 IMPLEMENTED BUT BROKEN | Fetch TIMEOUT preserved in nested summary but main final decision remains Legitimate with no incomplete-analysis state; H3. |
| HTML size | ✅ VERIFIED | Real BeautifulSoup output, fixture tests, difficult nested/unclosed HTML parsed without JavaScript execution. |
| Tag count | ✅ VERIFIED | Real BeautifulSoup output, fixture tests, difficult nested/unclosed HTML parsed without JavaScript execution. |
| Script count | ✅ VERIFIED | Real BeautifulSoup output, fixture tests, difficult nested/unclosed HTML parsed without JavaScript execution. |
| Iframe count | ✅ VERIFIED | Real BeautifulSoup output, fixture tests, difficult nested/unclosed HTML parsed without JavaScript execution. |
| Form count | ✅ VERIFIED | Real BeautifulSoup output, fixture tests, difficult nested/unclosed HTML parsed without JavaScript execution. |
| Input count | ⚠️ PARTIALLY IMPLEMENTED | Per-form field_count exists; no total numerical input_count; inputs outside forms excluded from password/hidden totals. |
| Password fields | ⚠️ PARTIALLY IMPLEMENTED | Inside-form detection tested; outside-form credential fields omitted and generic login form described as harvesting. |
| Hidden fields | ⚠️ PARTIALLY IMPLEMENTED | Inside-form detection tested; outside-form credential fields omitted and generic login form described as harvesting. |
| Credential form detection | ⚠️ PARTIALLY IMPLEMENTED | Inside-form detection tested; outside-form credential fields omitted and generic login form described as harvesting. |
| Password inputs | ⚠️ PARTIALLY IMPLEMENTED | Inside-form detection tested; outside-form credential fields omitted and generic login form described as harvesting. |
| Hidden inputs | ⚠️ PARTIALLY IMPLEMENTED | Inside-form detection tested; outside-form credential fields omitted and generic login form described as harvesting. |
| External resources | 🐛 IMPLEMENTED BUT BROKEN | Protocol-relative external action misresolved to page hostname; forms after first credential form may be ignored for indicators; H8. |
| Form action analysis | 🐛 IMPLEMENTED BUT BROKEN | Protocol-relative external action misresolved to page hostname; forms after first credential form may be ignored for indicators; H8. |
| Cross-domain form action | 🐛 IMPLEMENTED BUT BROKEN | Protocol-relative external action misresolved to page hostname; forms after first credential form may be ignored for indicators; H8. |
| Suspicious form behavior | 🐛 IMPLEMENTED BUT BROKEN | Protocol-relative external action misresolved to page hostname; forms after first credential form may be ignored for indicators; H8. |
| eval | ✅ VERIFIED | Static regex signatures exist and script tests/independent eval(atob()) fixture detect obfuscation; no evaluation. |
| Function | ✅ VERIFIED | Static regex signatures exist and script tests/independent eval(atob()) fixture detect obfuscation; no evaluation. |
| atob | ✅ VERIFIED | Static regex signatures exist and script tests/independent eval(atob()) fixture detect obfuscation; no evaluation. |
| unescape | ✅ VERIFIED | Static regex signatures exist and script tests/independent eval(atob()) fixture detect obfuscation; no evaluation. |
| Long encoded strings | ⚠️ PARTIALLY IMPLEMENTED | Hex/Unicode escape signatures detected; no dedicated long-base64/string-size heuristic; static signals are not evidence of executed behavior. |
| Obfuscation patterns | ⚠️ PARTIALLY IMPLEMENTED | Hex/Unicode escape signatures detected; no dedicated long-base64/string-size heuristic; static signals are not evidence of executed behavior. |
| No untrusted JavaScript execution | ✅ VERIFIED | Static parser and regex only. Dynamic mode performs no execution either. |
| Iframe count | ✅ VERIFIED | Source analysis and numerical count exercised by fixtures. |
| Iframe source | ✅ VERIFIED | Source analysis and numerical count exercised by fixtures. |
| External iframe domains | 🐛 IMPLEMENTED BUT BROKEN | Protocol-relative iframe source is omitted from external detection; H8. |
| Suspicious iframe relationships | 🐛 IMPLEMENTED BUT BROKEN | Protocol-relative iframe source is omitted from external detection; H8. |
| script src | ⚠️ PARTIALLY IMPLEMENTED | Selected absolute resources processed; protocol-relative paths missed; external_script_count counts sourced scripts rather than strictly different registrable domains. |
| iframe src | ⚠️ PARTIALLY IMPLEMENTED | Selected absolute resources processed; protocol-relative paths missed; external_script_count counts sourced scripts rather than strictly different registrable domains. |
| link href | ⚠️ PARTIALLY IMPLEMENTED | Selected absolute resources processed; protocol-relative paths missed; external_script_count counts sourced scripts rather than strictly different registrable domains. |
| Resource-domain mismatch | ⚠️ PARTIALLY IMPLEMENTED | Selected absolute resources processed; protocol-relative paths missed; external_script_count counts sourced scripts rather than strictly different registrable domains. |
| image src | ❌ NOT IMPLEMENTED | No general image/stylesheet resource inventory; special canonical/favicon links do not provide full stylesheet coverage. |
| stylesheet href | ❌ NOT IMPLEMENTED | No general image/stylesheet resource inventory; special canonical/favicon links do not provide full stylesheet coverage. |
| urgency_score | ✅ VERIFIED | Actual keyword category hit counts and normalized scores returned; runtime fixture produced urgency=1 and keyword_count=7. |
| financial_language_score | ✅ VERIFIED | Actual keyword category hit counts and normalized scores returned; runtime fixture produced urgency=1 and keyword_count=7. |
| login_language_score | ✅ VERIFIED | Actual keyword category hit counts and normalized scores returned; runtime fixture produced urgency=1 and keyword_count=7. |
| security_language_score | ✅ VERIFIED | Actual keyword category hit counts and normalized scores returned; runtime fixture produced urgency=1 and keyword_count=7. |
| phishing_keyword_count | ✅ VERIFIED | Actual keyword category hit counts and normalized scores returned; runtime fixture produced urgency=1 and keyword_count=7. |
| credential_request_score | ⚠️ PARTIALLY IMPLEMENTED | Equivalent key is credential_score; no context-sensitive NLP model. |
| Keyword is not automatic phishing | ✅ VERIFIED | Keywords create heuristic scores/indicators, not an automatic final phishing branch. Lack of integration is a separate H1 issue. |
| Contextual false-positive control | ⚠️ PARTIALLY IMPLEMENTED | Simple substring matches, title-brand exact-domain heuristic; limited semantic context. Official alternate domains can be flagged. |
| Dynamic isolated browser / sandbox | 🐛 IMPLEMENTED BUT BROKEN | allow_headless=True returns DYNAMIC_ANALYSIS_SUCCESS / HEADLESS_ISOLATED without launching a browser. Runtime checks demonstrate fabricated enforcement metadata; M5. |

## Phase 5 Verification

### Dataset and source-label integrity

**C1 — publisher labels are reversed in SecureSight.** [UCI's dataset page](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) defines **1 = legitimate and 0 = phishing**. `scripts/preprocess.py::_to_binary_label` preserves these integers; `data/metadata/label_definition.json`, inference and reports interpret **1 = phishing and 0 = legitimate**. Independent reconciliation normalized raw URLs with the actual preprocessing function and matched all **232,472 cleaned rows**: **232,472 preserve the source label, zero invert it**. The observed cleaned distribution is 134,849 source-legitimate rows and 97,623 source-phishing rows, misnamed in project metadata. The generated blacklist also selects label 1, so this error affects reputation as well as both URL models.

**H2 — stale/disconnected feature pipeline.** Actual parquet has **11 feature columns plus label**. Training renames those columns and zero-fills to 57; **46 canonical features are constant**, including every actual domain/HTML/content feature except the legacy HTTPS flag mislabeled as tls_valid. `dataset_hash.json` records the correct file bytes/hash but incorrectly describes it as containing 57 canonical columns plus label/domain. Live extraction loses url_len → url_length, url_entropy → entropy, etc.; domain code reads nonexistent summary/is_valid/days_until_expiration. Independent result: actual URL length 37 becomes 0; age 3,650 becomes 0; valid TLS becomes 0. A declared version/order does not repair these semantics.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| Dataset source | ⚠️ PARTIALLY IMPLEMENTED | Raw source documented; exact UCI page verified; manifest claims Phase 2–4 feature generation and licensing/approximate distribution inconsistent with real parquet/source; C1/H2. |
| Dataset provenance | ⚠️ PARTIALLY IMPLEMENTED | Raw source documented; exact UCI page verified; manifest claims Phase 2–4 feature generation and licensing/approximate distribution inconsistent with real parquet/source; C1/H2. |
| Labels documented | 🐛 IMPLEMENTED BUT BROKEN | Documented target semantics conflict with publisher and preserved raw values; C1. |
| Duplicate handling | ⚠️ PARTIALLY IMPLEMENTED | Current cleaned URLs have zero exact duplicates; actual preprocessing normalizes but keeps first conflicting label rather than documented majority/tie policy. Normalizer discards query/fragment and can merge semantically distinct URLs. |
| Malformed data handling | ⚠️ PARTIALLY IMPLEMENTED | Some URL errors/empty values filtered; no comprehensive production validator used for preprocessing; grouping falls back to unknown; strict row identity not enforced. |
| Missing-value handling | ⚠️ PARTIALLY IMPLEMENTED | Train-only imputer exists; align zero-fills but creates NaN in early missing columns if first canonical column absent; independent frame reproduced this. |
| Dataset version | ⚠️ PARTIALLY IMPLEMENTED | Metadata version exists; raw/cleaned/parquet SHA-256 all match recorded byte hashes; recorded parquet columns incorrect and artifacts lack immutable training-run/split provenance. |
| Dataset hash | ⚠️ PARTIALLY IMPLEMENTED | Metadata version exists; raw/cleaned/parquet SHA-256 all match recorded byte hashes; recorded parquet columns incorrect and artifacts lack immutable training-run/split provenance. |
| Class distribution | 🐛 IMPLEMENTED BUT BROKEN | Binary numerical counts verified; class names inverted. Source semantics must be repaired before metrics are meaningful. |
| Train/validation/test split | ⚠️ PARTIALLY IMPLEMENTED | Current domain-grouped split reproduced: train 157816, validation 34579, test 40077; disjoint domains enforced; documented stratification not performed, because domain-label array is unused. |
| Same URL leakage | ⚠️ PARTIALLY IMPLEMENTED | Current outer split groups registrable domains and current normalized URLs deduplicated. No evidence of current outer group overlap; saved artifact split is not reproducible, and no persisted row identities establish historical partitions. |
| Same normalized URL leakage | ⚠️ PARTIALLY IMPLEMENTED | Current outer split groups registrable domains and current normalized URLs deduplicated. No evidence of current outer group overlap; saved artifact split is not reproducible, and no persisted row identities establish historical partitions. |
| Same domain leakage | ⚠️ PARTIALLY IMPLEMENTED | Current outer split groups registrable domains and current normalized URLs deduplicated. No evidence of current outer group overlap; saved artifact split is not reproducible, and no persisted row identities establish historical partitions. |
| Near-identical page leakage | 🔍 CANNOT VERIFY | No stored HTML/page fingerprints or similarity clusters; cannot establish absence of cross-domain duplicates. |
| Phase 2–4 features actually used | 🐛 IMPLEMENTED BUT BROKEN | 11 legacy columns expanded with 46 constants; source extractors not invoked for training; main scan never invokes v5; H1/H2. |
| Feature names | 🐛 IMPLEMENTED BUT BROKEN | Live naming and domain structure mismatch training feature aliases; HTTPS substituted for certificate validity; H2. |
| Training/inference consistency | 🐛 IMPLEMENTED BUT BROKEN | Live naming and domain structure mismatch training feature aliases; HTTPS substituted for certificate validity; H2. |
| Feature order | ✅ VERIFIED | Saved schema has 57 ordered unique names and version 4.0; inference aligns in that order; feature-schema unit tests pass. This verifies shape/order, not feature correctness. |
| Feature schema version | ✅ VERIFIED | Saved schema has 57 ordered unique names and version 4.0; inference aligns in that order; feature-schema unit tests pass. This verifies shape/order, not feature correctness. |
| Preprocessing | ⚠️ PARTIALLY IMPLEMENTED | Saved median-imputer/scaler loads and transforms; current outer train-only fit verified in code. Preprocessing is fitted before internal CV/OOF, leaking fold statistics; H4. |
| Logistic Regression | ✅ VERIFIED | Actual fitted base estimators inspected in persisted stack, sklearn toy fit/predict tests pass; model code defines tuning/balanced class weights. |
| Random Forest | ✅ VERIFIED | Actual fitted base estimators inspected in persisted stack, sklearn toy fit/predict tests pass; model code defines tuning/balanced class weights. |
| XGBoost | ⚠️ PARTIALLY IMPLEMENTED | Optional implementation exists; the actual saved third estimator named xgb is ExtraTreesClassifier, not XGBoost. LR Pipeline and RandomForestClassifier are the other fitted estimators. |
| Hyperparameters | ⚠️ PARTIALLY IMPLEMENTED | Configured balanced weights, deterministic seed 42 and hyperparameter grids; verified toy behavior and source; domain stratification claim false; full retraining not run. |
| Class imbalance handling | ⚠️ PARTIALLY IMPLEMENTED | Configured balanced weights, deterministic seed 42 and hyperparameter grids; verified toy behavior and source; domain stratification claim false; full retraining not run. |
| Random seeds | ⚠️ PARTIALLY IMPLEMENTED | Configured balanced weights, deterministic seed 42 and hyperparameter grids; verified toy behavior and source; domain stratification claim false; full retraining not run. |
| Cross-validation | 🐛 IMPLEMENTED BUT BROKEN | _run_cv_stats calls undefined model_ctor rather than model_ctor_fn, returns cv_error; saved model_comparison has identical errors. Tuning/OOF use row StratifiedKFold, not domain-grouped folds, after outer preprocessing; H4. |
| Model selection | ⚠️ PARTIALLY IMPLEMENTED | Stacking/voting compared on validation F1; final persisted stacked model loads; historical selected split cannot be established. |
| Genuine ensemble | ✅ VERIFIED | Fitted stack inside CalibratedClassifierCV; clone fitted on training fold, predicts held-out fold, meta LR fit on OOF; toy ensemble probability/determinism tests pass. Fold domain/preprocessing leakage remains separate. |
| Out-of-fold predictions | ✅ VERIFIED | Fitted stack inside CalibratedClassifierCV; clone fitted on training fold, predicts held-out fold, meta LR fit on OOF; toy ensemble probability/determinism tests pass. Fold domain/preprocessing leakage remains separate. |
| Meta learner | ✅ VERIFIED | Fitted stack inside CalibratedClassifierCV; clone fitted on training fold, predicts held-out fold, meta LR fit on OOF; toy ensemble probability/determinism tests pass. Fold domain/preprocessing leakage remains separate. |
| Soft-voting weights based on validation evidence | ❌ NOT IMPLEMENTED | Weights fixed at [0.2,0.6,0.2], no validation-derived weight search; alternative ensemble comparison does not establish evidence-based weights. |
| Platt scaling | ⚠️ PARTIALLY IMPLEMENTED | Calibration helper supports sigmoid/isotonic; saved model is real isotonic CalibratedClassifierCV; calibration fit uses validation in current code. Calibration quality on the same validation samples is optimistic. |
| Isotonic calibration | ⚠️ PARTIALLY IMPLEMENTED | Calibration helper supports sigmoid/isotonic; saved model is real isotonic CalibratedClassifierCV; calibration fit uses validation in current code. Calibration quality on the same validation samples is optimistic. |
| Calibration does not leak test data | ⚠️ PARTIALLY IMPLEMENTED | Current main passes validation to calibration, not test. Historical model run unverified; H5. |
| Model probability distinguished from SecureSight risk | ✅ VERIFIED | Main scan returns separate ml_probability and heuristic risk_score; separate v5 endpoint returns probability/threshold, no unified risk score. |
| Threshold not blindly 0.5 | ✅ VERIFIED | Saved threshold 0.4; actual selection/evaluation functions pass controlled tests; results JSON exists and inference loads threshold. |
| Threshold analysis | ✅ VERIFIED | Saved threshold 0.4; actual selection/evaluation functions pass controlled tests; results JSON exists and inference loads threshold. |
| Precision/recall/FPR/FNR threshold evaluation | ✅ VERIFIED | Saved threshold 0.4; actual selection/evaluation functions pass controlled tests; results JSON exists and inference loads threshold. |
| Threshold uses validation | ⚠️ PARTIALLY IMPLEMENTED | Current training flow uses X_val probabilities; saved artifacts and historical split cannot be certified as current run. |
| Test not used to tune threshold | ⚠️ PARTIALLY IMPLEMENTED | Current training flow uses X_val probabilities; saved artifacts and historical split cannot be certified as current run. |
| Accuracy | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| Precision | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| Recall | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| F1 | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| ROC-AUC | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| PR-AUC | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| FPR | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| FNR | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| Confusion matrix | ⚠️ PARTIALLY IMPLEMENTED | Metric functions exercised; saved model evaluated on current reproduced partition. Numerical formulas work but targets inverted and historical test partition differs; table below. |
| Validation versus test distinction | ⚠️ PARTIALLY IMPLEMENTED | Code separates evaluations; saved threshold/evaluation samples differ as expected for different partitions, but saved final count also differs from reproducing current test, H5. |
| Final test set never used for tuning | 🔍 CANNOT VERIFY | No current outer test-to-tuning call found. Cannot prove never across historical iterations; saved split/report mismatch and absent immutable split history prevent PASS. No historical test leakage is asserted without evidence. |
| Model artifact | ✅ VERIFIED | All local v5 files exist, readable; load status OK, model 5.0.0, feature version 4.0, 57 inputs, threshold 0.4. Artifact validity is weaker than model/data semantic correctness. |
| Preprocessor | ✅ VERIFIED | All local v5 files exist, readable; load status OK, model 5.0.0, feature version 4.0, 57 inputs, threshold 0.4. Artifact validity is weaker than model/data semantic correctness. |
| Feature schema | ✅ VERIFIED | All local v5 files exist, readable; load status OK, model 5.0.0, feature version 4.0, 57 inputs, threshold 0.4. Artifact validity is weaker than model/data semantic correctness. |
| Model metadata | ✅ VERIFIED | All local v5 files exist, readable; load status OK, model 5.0.0, feature version 4.0, 57 inputs, threshold 0.4. Artifact validity is weaker than model/data semantic correctness. |
| Threshold | ✅ VERIFIED | All local v5 files exist, readable; load status OK, model 5.0.0, feature version 4.0, 57 inputs, threshold 0.4. Artifact validity is weaker than model/data semantic correctness. |
| Metrics | ✅ VERIFIED | All local v5 files exist, readable; load status OK, model 5.0.0, feature version 4.0, 57 inputs, threshold 0.4. Artifact validity is weaker than model/data semantic correctness. |
| Model version | ✅ VERIFIED | All local v5 files exist, readable; load status OK, model 5.0.0, feature version 4.0, 57 inputs, threshold 0.4. Artifact validity is weaker than model/data semantic correctness. |
| Dataset version linked to model | ⚠️ PARTIALLY IMPLEMENTED | Metadata links dataset/version/hash; erroneous feature provenance and unreproduced split prevent reliable end-to-end provenance. |
| Same preprocessing loaded at inference | ⚠️ PARTIALLY IMPLEMENTED | Saved imputer/scaler is used before prediction, matching current training structure; corrupt/missing preprocessor is silently ignored and actual historical run not certified. |
| Known legitimate predictions | ⚠️ PARTIALLY IMPLEMENTED | Two supplied fixtures predicted legitimate, but fixtures use legacy names; mostly ignored without explicit mapping. This cannot validate calibration/semantic correctness. |
| Known phishing predictions | 🐛 IMPLEMENTED BUT BROKEN | All four supplied known_phishing fixtures predicted legitimate, both raw and explicitly legacy-name mapped; regression tests only verify JSON structure, H3/M6. |
| Edge-case predictions | 🐛 IMPLEMENTED BUT BROKEN | Empty dictionary and wrong-schema/unrelated features return OK/legitimate with 0 probability. Missing required features never rejected; string nan accepted; H3. |
| Missing features | 🐛 IMPLEMENTED BUT BROKEN | Empty dictionary and wrong-schema/unrelated features return OK/legitimate with 0 probability. Missing required features never rejected; string nan accepted; H3. |
| Schema mismatch | 🐛 IMPLEMENTED BUT BROKEN | Empty dictionary and wrong-schema/unrelated features return OK/legitimate with 0 probability. Missing required features never rejected; string nan accepted; H3. |
| Malformed numeric vector | ✅ VERIFIED | Numeric NaN/non-numeric values rejected; missing model emits MODEL_NOT_FOUND with null prediction. String non-finite path remains a bug. |
| Missing model | ✅ VERIFIED | Numeric NaN/non-numeric values rejected; missing model emits MODEL_NOT_FOUND with null prediction. String non-finite path remains a bug. |
| Prediction/probability/model version/schema version/threshold returned | ✅ VERIFIED | Actual saved-model output includes these fields; see runtime_results.json. |
| Safe inference failure | ⚠️ PARTIALLY IMPLEMENTED | Direct v5 prediction failure returns PREDICTION_FAILED/null prediction, verified. Main legacy path substitutes 0.5 then Legitimate for absent model; H3. |
| Global/local explanation foundation | ⚠️ PARTIALLY IMPLEMENTED | Feature importance calculation code exists; inference local explanation ranks raw magnitudes and prediction-dependent signs, not learned contributions; L2. |

### Saved metrics versus independent current-partition evaluation

These numbers measure repository target integers, **not validated phishing performance**, because C1 reverses the labels. A better-looking independent number does not establish readiness.

| Metric | Saved final report | Re-evaluated saved model on current code partition |
|---|---:|---:|
| accuracy | 0.991771 | 0.993787 |
| precision | 0.991226 | 0.990939 |
| recall | 0.996037 | 0.996847 |
| f1 | 0.993626 | 0.993884 |
| roc_auc | 0.995965 | 0.998461 |
| pr_auc | 0.995755 | 0.997304 |
| false_positive_rate | 0.015943 | 0.009353 |
| false_negative_rate | 0.003963 | 0.003153 |
| Samples | 31354 | 40077 |

Saved confusion: TN=10,987, FP=178, FN=80, TP=20,109. Reproduced current partition: TN=19,595, FP=185, FN=64, TP=20,233. The current test count **40,077** does not equal saved **31,354**. Hashes agree for source files; changed partition logic/row mapping or a different run must be reconciled. Re-evaluated rows must not be advertised as a newly independent untouched holdout: they may overlap the artifact's historical train/validation set. Full retraining was deliberately not performed during this read-only audit.

## End-to-End Verification

Seven cases used the **actual Flask endpoint, strict input validation, real legacy model, advanced extractor, domain orchestration, fetch loop, BeautifulSoup and NLP**. DNS/TLS/WHOIS/HTTP responses were controlled fixtures; no live phishing or private targets were contacted. The phishing example is a synthetic Microsoft-impersonation credential fixture, not a verified currently active phishing URL. Domains under `.invalid` deliberately do not exist. Default suffix extraction treats unsupported `.invalid` hosts as sharing registrable `invalid`, another limitation of domain equality on unsupported suffixes.

Every valid scan produced legacy 11-feature ML, appended Phase 2–4 details and **never invoked Phase 5**. Thus isolated successful stages do not constitute a five-phase end-to-end PASS. Full response/evidence and warning details are retained in runtime_results.json.

| Case / input | Phase 2 | Phase 3 DNS | Phase 4 | Vector / ML | Final response | Warnings | Latency ms |
|---|---|---|---|---|---|---|---:|
| legitimate: `https://example.com/` | 50 features | SUCCESS | SUCCESS | legacy 11; p=0.074; v5 absent | HTTP 200; Legitimate | none | 62.519 |
| phishing_fixture: `https://credential-fixture.invalid/login` | 50 features | SUCCESS | SUCCESS | legacy 11; p=0.001; v5 absent | HTTP 200; Legitimate | PASSWORD_FORM_PRESENT, BRAND_DOMAIN_MISMATCH, URGENT_PHISHING_LANGUAGE | 68.943 |
| malformed: `javascript:alert(1)` | 0 features | not reached | not reached | not reached | HTTP 400; INVALID_URL | none | 1.539 |
| redirect: `https://example.com/redirect` | 50 features | SUCCESS | SUCCESS | legacy 11; p=0.0; v5 absent | HTTP 200; Legitimate | none | 58.402 |
| domain_unavailable: `https://unavailable.invalid/` | 50 features | DOMAIN_NOT_FOUND | SSRF_BLOCKED | legacy 11; p=0.071; v5 absent | HTTP 200; Legitimate | SSRF_BLOCKED | 46.92 |
| difficult_html: `https://example.com/difficult` | 50 features | SUCCESS | SUCCESS | legacy 11; p=0.0; v5 absent | HTTP 200; Legitimate | PASSWORD_FORM_PRESENT, OBFUSCATED_SCRIPT_DETECTED | 57.159 |
| partial_failure: `https://example.com/timeout` | 50 features | SUCCESS | TIMEOUT | legacy 11; p=0.0; v5 absent | HTTP 200; Legitimate | none | 43.489 |

### Failure-state verification

| Forced failure | Observed behavior | Status |
|---|---|---|
| DNS unavailable | DOMAIN_NOT_FOUND nested DNS; SSRF_BLOCKED webpage; final Legitimate | 🐛 IMPLEMENTED BUT BROKEN |
| Unsafe resolved DNS | TLS analyzer still called once; private connection captured by trap | 🐛 IMPLEMENTED BUT BROKEN |
| TLS connection failure | UNAVAILABLE, error message; no top-level incomplete scan | ⚠️ PARTIALLY IMPLEMENTED |
| Reputation all ERROR | Aggregator UNAVAILABLE, provider ERROR retained | ✅ VERIFIED |
| Configured external skeleton | SAFE 0.8 / API lookup clean without lookup | 🐛 IMPLEMENTED BUT BROKEN |
| Fetch timeout | TIMEOUT nested fetch; empty normal features; final Legitimate; no webpage warning | 🐛 IMPLEMENTED BUT BROKEN |
| HTML parser exception | ValueError escapes stage; generic API handler rather than HTML_PARSE_FAILED | ⚠️ PARTIALLY IMPLEMENTED |
| Legacy model missing | model_available=false, probability=0.5, final Legitimate | 🐛 IMPLEMENTED BUT BROKEN |
| V5 model missing / failure | MODEL_NOT_FOUND or PREDICTION_FAILED with null prediction | ✅ VERIFIED |
| Feature invalid numeric | INVALID_FEATURE_VECTOR | ✅ VERIFIED |
| Missing/schema-mismatched feature dictionary | OK, legitimate, probability=0 | 🐛 IMPLEMENTED BUT BROKEN |
| API malformed URL | HTTP 400 INVALID_URL with safe text/request ID | ✅ VERIFIED |
| Feature extraction exception through API | HTTP 500 INTERNAL_ERROR; internal sentinel absent from response | ✅ VERIFIED |
| V5 model load exception through API | HTTP 503 but internal sentinel/path returned verbatim | 🐛 IMPLEMENTED BUT BROKEN |
| All scan semaphore slots occupied | Scan returns HTTP 503; ML endpoint still returns 200 with empty-vector prediction | 🐛 IMPLEMENTED BUT BROKEN |

## Security Audit

**FAIL.** Legacy safeguards cannot be generalized to every outbound client. The independent rebinding experiment supplied a public preflight result and then loopback on the connection resolver. Real requests code attempted socket address **127.0.0.1:80**, intercepted before any packet. Real TLS code likewise attempted **127.0.0.1:443**. Strict TLS certificate verification cannot prevent the initial private-network connection. Consolidated as C2. [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) supports checking address safety at the network boundary and accounting for DNS changes.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| SSRF | 🐛 IMPLEMENTED BUT BROKEN | C2: real socket traps show private connection attempts. No exploit packet sent; cloud metadata fetch not performed. Legacy literal metadata rejection passes but later hostname resolution bypasses boundary. |
| DNS rebinding | 🐛 IMPLEMENTED BUT BROKEN | C2: real socket traps show private connection attempts. No exploit packet sent; cloud metadata fetch not performed. Legacy literal metadata rejection passes but later hostname resolution bypasses boundary. |
| Private IP access | 🐛 IMPLEMENTED BUT BROKEN | C2: real socket traps show private connection attempts. No exploit packet sent; cloud metadata fetch not performed. Legacy literal metadata rejection passes but later hostname resolution bypasses boundary. |
| Cloud metadata access | 🐛 IMPLEMENTED BUT BROKEN | C2: real socket traps show private connection attempts. No exploit packet sent; cloud metadata fetch not performed. Legacy literal metadata rejection passes but later hostname resolution bypasses boundary. |
| Unsafe redirects | ⚠️ PARTIALLY IMPLEMENTED | Redirect count bounded/preflight checked; full URL revalidation and IP pinning missing. |
| Unsafe URL schemes | ✅ VERIFIED | API validator rejects dangerous schemes; redirect-specific validation remains partial. |
| Unbounded downloads | ⚠️ PARTIALLY IMPLEMENTED | Body bytes bounded but overall deadline and response/session cleanup incomplete. |
| Unbounded HTML | ⚠️ PARTIALLY IMPLEMENTED | Fetched body capped at 1 MiB; no structural node/depth/resource or CPU deadline, H7. |
| Unbounded DOM processing | ⚠️ PARTIALLY IMPLEMENTED | Fetched body capped at 1 MiB; no structural node/depth/resource or CPU deadline, H7. |
| Unsafe JavaScript execution | ✅ VERIFIED | No untrusted execution found in reachable static or fake dynamic path. |
| Command injection | ⚠️ PARTIALLY IMPLEMENTED | No reachable user-controlled shell command, filesystem target selection or SQL layer found in reviewed Phase 1–5 paths. Not a formal exhaustive proof; fixed script subprocess argv is offline. |
| Path traversal | ⚠️ PARTIALLY IMPLEMENTED | No reachable user-controlled shell command, filesystem target selection or SQL layer found in reviewed Phase 1–5 paths. Not a formal exhaustive proof; fixed script subprocess argv is offline. |
| SQL injection | ⚠️ PARTIALLY IMPLEMENTED | No reachable user-controlled shell command, filesystem target selection or SQL layer found in reviewed Phase 1–5 paths. Not a formal exhaustive proof; fixed script subprocess argv is offline. |
| XSS | ⚠️ PARTIALLY IMPLEMENTED | Jinja autoescape/nonce CSP and file-name textContent reviewed; no live browser exploit test performed. HTML retained for analysis, not executed. |
| Unsafe deserialization | ⚠️ PARTIALLY IMPLEMENTED | joblib loads local trusted artifacts, not public uploaded model files; model artifacts still require trusted supply chain and matching runtime. No runtime integrity signature or quarantine. |
| Hard-coded API keys | ⚠️ PARTIALLY IMPLEMENTED | None found in reviewed source; test fixture keys synthetic; historical Git/external secret services not verified. |
| Secret leakage | 🐛 IMPLEMENTED BUT BROKEN | Detailed ML load/predict exceptions and model paths returned to client; M2. No real secret exposed during audit. |
| Safe errors | 🐛 IMPLEMENTED BUT BROKEN | Detailed ML load/predict exceptions and model paths returned to client; M2. No real secret exposed during audit. |
| Sensitive URL logging | ⚠️ PARTIALLY IMPLEMENTED | Central event logger avoids content; registration exception log and later raw error text can include URL/query. Full deployment log retention/proxy logs unverified. |
| Weak CORS | ✅ VERIFIED | Explicit origins and rejection tests; no wildcard production origins; trusted host settings validated. |
| Missing authentication | ❌ NOT IMPLEMENTED | Public scanner, no admin/training APIs; deployment decision about access control unresolved, not automatically critical. |
| Missing authorization | ❌ NOT IMPLEMENTED | Public scanner, no admin/training APIs; deployment decision about access control unresolved, not automatically critical. |
| Rate-limit bypass | ⚠️ PARTIALLY IMPLEMENTED | POST quota shared across endpoints and ignores untrusted forwarded headers. New expensive endpoints evade concurrency semaphore, not request quota. Multi-worker/public-proxy enforcement not exercised. |

## Dependency Audit

- `pip check`: **No broken requirements found**, but this only checks metadata of installed packages; it did not detect absent application dependency BeautifulSoup.
- `pip-audit -r requirements.txt`: **42 resolved packages, zero known vulnerabilities**; installed-environment audit also **zero known vulnerabilities** on 8 October 2026. The missing parser was audited through requirements resolution. Neither result addresses application SSRF or ML integrity.
- Installed environment lacks `beautifulsoup4`; isolated exact declared version used only for audit. Optional torch/transformers are not installed/verified; image capability is outside Phase 1–5 URL claims.
- Outdated check found 28 installed packages, including sklearn 1.5.1, pandas 2.2.2, numpy 1.26.4, imbalanced-learn 0.12.4, joblib 1.4.2, Gunicorn 22.0.0 and tldextract 5.1.2. Newest is not necessarily compatible. No upgrades performed; full versions in outdated.json.
- Legacy artifacts emit InconsistentVersionWarning: trained sklearn 1.4.2 versus runtime 1.5.1; saved v5 environment declares 1.5.1 and loaded successfully. [scikit-learn model persistence guidance](https://scikit-learn.org/stable/model_persistence.html#security-maintainability-limitations) does not support cross-version loading as a reliable deployment contract.
- Flask-Limiter 4.1.1 removed the test's `flask_limiter.extension` import target; production backend-failure test fails before checking its intended behavior.
- XGBoost is optional with ExtraTrees fallback. imbalanced-learn is declared but the current main training flow uses balanced weights, not a SMOTE operation. Gunicorn is a Linux deployment dependency, not a native Windows test server.
- No duplicate pinned project package entry requiring consolidation found; optional image requirements intentionally include base requirements. Unused imports and fallback packages merit cleanup, not blind removal.
- Bandit: **17 low-severity findings, no high/medium findings** in scanned app/utils/ml. Most are broad exception pass/continue and assert checks. These are tool signals, consolidated where meaningful; they do not detect the verified SSRF flaws.
- Focused flake8 E9/F63/F7/F82: **2 F821 errors**, undefined `model_ctor` and missing Optional import. The latter is an annotation issue and did not crash ensemble construction; the former actually disables reported CV statistics.
- Docker compose config parses successfully; Docker info fails because Docker Desktop Linux engine is unavailable. Container build, shared Redis production runtime, deployment and Gunicorn behavior **CANNOT VERIFY**.

## Performance Audit

All timings are this audit machine's measurements. Public DNS/TLS/web fetch timings were not measured because network was deliberately controlled; fixture timing only measures local orchestration. Dataset label reconciliation and memory include local data/model loading, not an idle production worker baseline.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| URL parsing | ✅ VERIFIED | 0.8 ms, real advanced extraction |
| DNS latency | 🔍 CANNOT VERIFY | Real network unavailable in this test; local stub 0.054 ms; configured 1 ms timeout exceeded by controlled resolver at 50.57 ms |
| TLS latency | 🔍 CANNOT VERIFY | Public certificate handshake unmeasured; failed socket-trap path 62.266 ms |
| Reputation latency | ✅ VERIFIED | Local blacklist 0.017 ms; external providers not implemented |
| Web fetch latency | 🔍 CANNOT VERIFY | Controlled HTTP fixture, no public-network throughput/deadline guarantee; total end-to-end fixture timings shown above |
| HTML analysis latency | ✅ VERIFIED | DOM-only small fixture 0.294 ms; difficult HTML + NLP 11.692 ms |
| ML inference latency | ✅ VERIFIED | Real v5 end-to-end validation/preprocess/predict: mean 13.43 ms; range 12.38–16.74 ms over 10 calls; initial model load 988.6 ms |
| Total analysis latency | ⚠️ PARTIALLY IMPLEMENTED | Valid mocked-network API cases 43.49–68.94 ms; v5 not included by scan; no production SLO measured |
| Memory usage | ✅ VERIFIED | Independent audit process Windows working set 493.7 MiB, peak 711.5 MiB, after dataset/model loading; not a worker baseline |

Likely operational bottlenecks: synchronous DNS/TLS/WHOIS/fetch serial stages, potentially unbounded getaddrinfo and slow streaming body, duplicated parsing/resolution, large legacy model loading and unbounded cache. Measured local CPU bottleneck is model inference versus lexical extraction; remote bottlenecks require a later controlled network benchmark. No optimization or source change was made.

## Test Suite Results

| Run | Total | Passed | Failed | Skipped | Errors | Duration |
|---|---:|---:|---:|---:|---:|---|
| Original venv full discovery | Collection aborted | 0 executed | 0 executed | 0 recorded | 2 | 40.86 s |
| Project-only, isolated declared parser dependency | 180 | 179 | 1 | 0 | 0 | 23.55 s |
| Broad discovery including vendored dependency tests, excluded from project count | 844 | 638 | 3 | 203 | 0 | 105.75 s |

Coverage: **not available**; coverage/pytest-cov not installed. No percentage inferred from passing test counts. Focused lint failed with two F821 findings. Docker runtime not tested. No full model retraining or browser rendering was performed.

Failing project test: `tests/test_security.py::test_production_headers_and_backend_failure` monkeypatches `flask_limiter.extension.storage_from_string`, which does not exist in Flask-Limiter 4.1.1. It fails before its intended production HSTS/Redis failure assertions; this is a broken test compatibility path, not proof those production controls are broken.

Test quality findings:

- `TestRegressionFixtures` only reads JSON, checks fields/labels and file existence; it never tests predicted classes. Independent saved-model calls found all four phishing fixtures classified legitimate.
- Dataset duplicate test checks parquet length <= cleaned CSV length rather than normalized URL/domain partition identities. Binary-label/distribution checks cannot catch the publisher's reversed semantics.
- Ensemble determinism test is meaningful for reproducibility, but not proof of domain-aware OOF or fold-local preprocessing. Tests do not assert the `_run_cv_stats` success contract; persisted cv_error went unnoticed.
- Missing-column feature test always supplies the first canonical column, missing the reproduced early-NaN bug.
- Security tests for the legacy pinned gateway are useful but do not cover newer Phase 3 TLS/Phase 4 actual socket destinations. Passing preflight mocks do not establish SSRF safety.
- Autouse socket connect/connect_ex/sendto blocking does not block OS getaddrinfo DNS lookups. Consequently the suite is not completely offline/deterministic for domain API checks; real DNS timing can affect results.
- Some v5 tests skip if the model file is absent; no such skip occurred in the project-only run. No empty/pass-only project test was identified in reviewed tests. Abstract provider `pass` methods are not tests.
- The broad discovery rerun inadvertently collected BeautifulSoup's vendored tests. Two dependency compatibility failures and 203 dependency skips are not attributed to SecureSight. The subsequent explicit `pytest tests` run is the authoritative suite count. Automatic approval review rejected cleanup of the newly installed vendor test folder as blocked by policy, so these audit dependencies remain; use explicit `pytest tests` to exclude them. Implementation and project tests were not changed.

## Documentation/Implementation Mismatches

| Claim | Actual evidence | Result |
|---|---|---|
| Phases 1–5 fully integrated | Main scan uses legacy model; v5 accepts raw features separately | 🐛 IMPLEMENTED BUT BROKEN |
| Phase 2 approximately 62 features | Actual extraction returns 50 | ⚠️ PARTIALLY IMPLEMENTED |
| Canonical 55-feature vector | Actual order/schema has 57 | ⚠️ PARTIALLY IMPLEMENTED |
| Training uses Phase 2–4 feature vectors | Actual parquet 11 legacy inputs; 46 zero constants | 🐛 IMPLEMENTED BUT BROKEN |
| Hash metadata lists canonical parquet columns + domain | Byte hashes match, physical file has 12 columns including label | 🐛 IMPLEMENTED BUT BROKEN |
| Source labels are 0 legitimate / 1 phishing | UCI explicitly defines reverse; all cleaned labels preserved | 🐛 IMPLEMENTED BUT BROKEN |
| Stratified grouped 70/15/15 | Domain shuffle by permutation, label array unused; sample proportions differ | ⚠️ PARTIALLY IMPLEMENTED |
| CV summary validated | Every recorded base cv_stats contains NameError | 🐛 IMPLEMENTED BUT BROKEN |
| Leakage-free stacking | OOF by rows; preprocessing fit on all outer training before folds | ⚠️ PARTIALLY IMPLEMENTED |
| Untouched final test metrics reproducible | Current test 40077 versus stored 31354; historical run identity absent | 🔍 CANNOT VERIFY |
| Conflicting labels majority, tie phishing | Actual dedup keeps first label | ⚠️ PARTIALLY IMPLEMENTED |
| Safe fetch / DNS rebinding mitigated globally | Legacy transport pinned; later TLS/fetch can connect private | 🐛 IMPLEMENTED BUT BROKEN |
| External clean reputation with configured key | Placeholder returns SAFE without external call | 🐛 IMPLEMENTED BUT BROKEN |
| Isolated dynamic/headless browser implemented | Metadata simulation claims success/isolation | 🐛 IMPLEMENTED BUT BROKEN |
| Regression fixtures verify classifier quality | JSON-only tests; supplied phishing fixtures return legitimate | 🐛 IMPLEMENTED BUT BROKEN |
| Ready for production / Phase 6 | Multiple security/data/integration blockers remain | 🐛 IMPLEMENTED BUT BROKEN |

Existing documentation was not edited during verification. Corrections should follow implementation decisions rather than cosmetically marking failures complete.

## Critical Issues

### C1 — Dataset class semantics inverted (ML + reputation)

**Evidence:** scripts/preprocess.py lines 50–69; metadata label_definition; all 232472 reconciled source rows preserve integers; UCI publisher encoding; inference predicts column 1 as phishing; blacklist generation selects label 1. **Impact:** high numerical accuracy is a score against mislabeled security meaning, and legitimate domains can populate the phishing blacklist. **Required fix later:** source-specific label mapping, immutable corrected dataset/blacklist, regenerate features, retrain/calibrate/evaluate both URL models with correct meaning and new holdout. Merely relabeling a report is insufficient.

### C2 — Private-network outbound access through later TLS/fetch clients

**Evidence:** utils/domain_intelligence.py calls analyze_tls_certificate regardless of unsafe DNS; tls_intelligence.py resolves by hostname again; safe_fetch.py passes hostname to requests after separate preflight. Independent traps recorded 127.0.0.1:443 and :80 connection attempts before packets. **Impact:** untrusted public hostnames/rebinding can reach internal targets; HTTPS verification occurs after connection. **Required fix later:** one validated, pinned outbound gateway reused by every stage and redirect, bounded resolver, matching SNI/Host/certificate validation, explicit proxy policy and total deadlines. Test actual socket destinations, including metadata/tunnel/rebinding cases.

## High Issues

1. **H1 — Five-phase scan not integrated.** app/services/scans.py computes final legacy/heuristic decision, appends advanced evidence, never aggregates/calls v5. Phishing credential HTML fixture still returns Legitimate. A unified documented decision/error contract is required.
2. **H2 — Feature semantics/training disconnect.** ml/features.py mismatches names/domain payload; training only renames legacy11, fills46 constants, HTTPS renamed tls_valid; metadata's parquet column claims false. Require one canonical typed/versioned generator for training and serving, with source completeness/missingness.
3. **H3 — Insufficient/failed intelligence becomes Legitimate.** Missing legacy model → 0.5 → Legitimate; fetch/DNS failures still produce confident top-level verdict. Empty/wrong-schema v5 vector → OK/legitimate/0; string non-finite values bypass validation. Require explicit unavailable/partial status and minimum valid feature contract.
4. **H4 — ML cross-validation integrity broken.** Undefined model_ctor disables reported CV; imputation/scaling occurs before tuning/OOF folds; row folds permit same-domain correlation. Fix fold-local pipelines with grouped CV/OOF. [scikit-learn guidance](https://scikit-learn.org/stable/modules/cross_validation.html) explains that transformations must be learned inside training partitions.
5. **H5 — Saved holdout/provenance not reproducible.** Current partition40077 vs saved31354; no immutable split IDs/run history; inferred features contradict physical dataset. Cannot certify final test never informed historical tuning; do not assert detected historical leakage. Freeze corrected source/row hashes/splits and preserve one untouched final evaluation.
6. **H6 — Reputation asserts unsupported safety.** Configured external skeleton returns SAFE/0.8 without request; default local non-hit returns SAFE instead of UNKNOWN; failures plus local non-hit can look safe. Preserve absence/unavailability and provider evidence; disable placeholders from any deployable provider selection.
7. **H7 — Work/resource bounds incomplete.** getaddrinfo ignores configured deadline, socket.setdefaulttimeout races across threads, no end-to-end streaming deadline/node cap, new heavy endpoints bypass semaphore, cache can grow without bound. Independent deadline test exceeds timeout; limit every expensive stage/endpoint.
8. **H8 — Credential exfiltration/domain mismatch missed.** Protocol-relative form/iframe/script destinations misinterpreted; unsupported suffix fallback groups unrelated .invalid hosts; first credential form can hide a later external credential form. Normalize all resource URLs with correct URL joining/base handling and examine every credential form.

## Medium Issues

1. **M1 — Declared parser missing from current runtime.** App/test import blocked without bs4; verify reproducible environment/container installation rather than accepting pip check alone.
2. **M2 — Inconsistent errors disclose implementation detail.** New ML endpoint returns raw exception/path text; registration exception logs may contain sensitive values. Return safe stable codes, content-free correlated logs.
3. **M3 — Domain cache incorrect/incomplete lifecycle.** Scheme/port omitted from key; HTTP→HTTPS returns non-TLS cached result; expired unvisited keys retained. Use context-aware bounded cache and freshness metadata.
4. **M4 — Fetch contract/cleanup faulty.** HTTP500 fixture returns SUCCESS; absent Content-Type accepted; sessions/responses not closed on returns/redirects, risking socket/resource leaks. Distinguish successful retrieval, unexpected status/type and always close resources.
5. **M5 — Dynamic isolation claims fabricated.** allow_headless=True returns success without browser; static fallback reports one document request even fetch failed. Return explicit unsupported/skipped states and only observed evidence.
6. **M6 — Test integrity/coverage gaps.** One production test broken; JSON-only regression fixtures conceal wrong predictions; absence of connection-boundary/new-stage integration tests and OS DNS isolation. Restore meaningful assertions and CI dependency installation.
7. **M7 — Legacy artifact/runtime version mismatch.** sklearn1.4.2 serialized artifacts load in1.5.1 with warnings; no strict compatible environment or readiness covering v5/schema/preprocessor. Version and validate all mandatory artifacts before ready state.

## Low Issues

1. **L1 — Documentation/count consistency.** 62/55 feature comments and completion wording conflict with50/57 reality; optional capabilities presented more strongly than evidence supports. Regenerate factual implementation status after fixes.
2. **L2 — Local explanation misleading.** Inference ranks absolute raw magnitudes and assigns direction based on predicted label, not model contribution; domain age/URL length units dominate. Explicitly label heuristic hints; validate explanation method before presenting causal claims.
3. **L3 — Dependency/maintenance cleanup.** Outdated packages, unused imports and optional fallback dependencies need deliberate compatibility review; no blanket upgrades or removal required for this audit.

## Phase Scores

Weights: completeness40%, correctness25%, security20%, testing10%, documentation5%. Component values below are engineering assessments from the requirement statuses/evidence, not a test-pass percentage. Round half up to whole scores; overall uses unrounded weighted scores equally across the five phases.

| Phase | Completeness | Correctness | Security | Testing | Documentation | Weighted score | Rounded |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | 85 | 70 | 40 | 70 | 65 | 69.75 | 70 |
| 2 | 70 | 65 | 85 | 70 | 60 | 71.25 | 71 |
| 3 | 55 | 40 | 15 | 50 | 30 | 41.50 | 42 |
| 4 | 60 | 45 | 20 | 55 | 30 | 46.25 | 46 |
| 5 | 55 | 15 | 40 | 40 | 20 | 38.75 | 39 |

Rationale: Phase1 has a solid foundation whose guarantees are undermined by new clients and a failing production check. Phase2 performs useful deterministic lexical analysis with missing schema/statistics and some incorrect indicators. Phase3's transport/reputation/cache guarantees are unreliable. Phase4 has real static analysis but insecure retrieval and incorrect domain/resource handling. Phase5 has real trained stacking/calibration/inference machinery, but reversed target semantics, stale vectors, unsafe missingness and unreproducible holdout invalidate the practical classifier.

## Overall Score

**54/100** (unrounded53.50). Mean of weighted phase scores; no bonus for passing tests that do not assert the required security/data semantics.

## Readiness Status

| Phase | Classification | Main reason |
|---|---|---|
| 1 | 🟡 NEEDS FIXES | Existing foundation; security boundary no longer universal, runtime/test compatibility gaps |
| 2 | 🟡 NEEDS FIXES | Lexical core exists; schema/features/IPv6/context incomplete |
| 3 | 🔴 NOT READY | Private TLS access, unsupported SAFE evidence, unbounded DNS/cache |
| 4 | 🔴 NOT READY | Rebinding/private fetch risk, missed credential domains, incomplete bounded processing |
| 5 | 🔴 NOT READY | Inverted labels, stale feature semantics, no unified scan integration, uncertified saved holdout |

Phase2 lexical endpoint can work independently; that does not make the complete system safe or complete. Historical test-set audit cannot receive PASS without evidence; ML and test integrity gate remain FAIL overall.

## Critical Blockers

### Critical Blockers Before Phase 6

1. Correct publisher label semantics and regenerate trustworthy dataset, blacklist, features/models/calibration/evaluation artifacts.
2. Eliminate private/rebinding connections across DNS/TLS/HTTP/redirects with one enforceable outbound boundary.
3. Use compatible canonical Phase2–4 features for training/inference and integrate v5 into the main scan decision.
4. Replace unsupported SAFE/Legitimate fallbacks with explicit unavailable/partial/error contracts, including missing/wrong-schema feature inputs.
5. Repair CV/fold preprocessing, freeze immutable group split/run provenance, and produce a reproducible untouched final evaluation.
6. Enforce resolver/total-fetch/DOM/cache/concurrency limits; restore security and meaningful classifier integration tests in a reproducible runtime.

## Non-Blocking Improvements

- Improve presentation/SEO only after truthful security behavior; no measured SEO deployment acceptance claim.
- Label heuristic explanations and replace magnitude-based hints when model attribution is required.
- Consolidate obsolete feature counts/docs and review optional/outdated dependencies with compatibility evidence.
- Establish controlled production-like latency/memory SLOs after the corrected safe pipeline is integrated.

## Recommended Fix Order

1. Prevent unsafe outbound connections; make failures explicit and disable fabricated provider safety claims.
2. Freeze source data meaning with source-specific label mapping and correct blacklist; invalidate old semantic performance claims.
3. Define a single feature/schema/missingness contract; generate actual Phase2–4 training evidence and integrate main scan with v5.
4. Implement grouped fold-local training, legitimate calibration/threshold selection and immutable final holdout provenance; retrain/evaluate without consuming the final set during development.
5. Repair form/resource resolution, bounded DNS/fetch/DOM/cache work, error sanitization and artifact readiness/version enforcement.
6. Restore project dependency installation and production test compatibility; add actual inference/SSRF socket/integration assertions, rerun complete suite/security audit and verify container/Redis runtime.
7. Update completion reports to the verified results and repeat this readiness audit before Phase6.

## Final Recommendation

**MAJOR REWORK REQUIRED**

Verification is complete within the recorded runtime limits. No implementation fixes or Phase6 work were started. The report distinguishes confirmed defects, controlled-runtime evidence and unavailable historical/network/deployment evidence; passing isolated unit tests cannot override the confirmed security/data/integration blockers.
