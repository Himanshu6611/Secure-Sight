# SecureSight Phase 9 verification report

Date: 2026-10-08. Status: implemented and verified within documented limits; **not a public-release accuracy certification**. The updated Phase_09_Updated.md scope was used. Phase 10 was not implemented.

## Verified behavior

Integrated URL scans expose a versioned brand/domain/history evidence graph, conservative corroborated brand mismatch, a bounded robots-aware same-host crawler, IANA-discovered RDAP with WHOIS fallback, and separate registration/website/page ages. The existing root fetch and final Phase 8 destination are reused. Child redirects cannot leave the final registrable site or the hostname whose robots policy was checked. Child-page first observations are also recorded.

Phase 6 policy 6.2.0 remains the score/verdict authority. Phase 7 registry 7.2.0 translates verified known observations. Phase 9 feature version is 9.0.0; serving model/schema stay 5.1.1 with 97 aggregate fields and 59 learned URL fields. No model retraining, feature appending, immutable brand whitelist or new scan endpoint was introduced. Optional bounded email_context extends the existing scan endpoint.

The title is excluded from visible-body evidence. Equally strong multi-brand claims remain ambiguous. Scored mismatch requires multiple page fields plus applicable credential/destination evidence. Similarity, age, IDN, HTTPS, brand match, redesign and historical changes do not alone produce phishing. Contextual history/spelling/email reasons add zero separate score points. Unverified external credential collection prevents an unwarranted legitimate verdict without inventing a corroborated brand floor. A verified destination on one form cannot hide an additional unverified collector on the same page.

## Completion matrix

| Requested capability | Result | Evidence and limits |
|---|---|---|
| Deep website inspection | PASS, bounded scope | Existing DOM parser plus sanitized counts, registry claims, JSON-LD/OG declared domains and fingerprints. No arbitrary page text retained. |
| Controlled crawler | PASS | Root reuse, robots, priorities, duplicate/scope/request/depth/body/time limits, per-child first observations, offline boundary fixtures and actual live budget stops. Sitemap expansion unavailable. |
| RDAP | PASS | IANA discovery and actual Verisign domain objects for PayPal, Microsoft and GitHub; bounded pinned JSON and validated registration dates. |
| WHOIS fallback | PASS fixtures; LIMITED live coverage | Actual parser tested on fixtures, including future-date rejection and partial RDAP preservation. Live samples succeeded through RDAP, so they did not validate live port-43 availability. |
| Domain age | PASS | Only creation/registration event defines age; invalid/future/missing dates remain null. |
| Website first seen | LIMITED | Earliest retained hostname observation by this process; not global website creation. |
| Page first seen | LIMITED | Separate hashed host/path key; query/fragment URLs excluded; child pages included. No verified creation date. |
| Historical web intelligence | LIMITED | Bounded process-local fingerprints and count changes; 512 keys, eight snapshots, 24-hour retention; resets on restart/eviction. |
| Certificate history | LIMITED | Current TLS metadata differences only. CT/external historical certificates unavailable. |
| DNS history | LIMITED | Current DNS observations/differences only. External passive DNS history unavailable. |
| Brand detection | PASS curated scope | PayPal, Microsoft, Google, GitHub, Apple; selected aliases/domains and official source links. Registry is incomplete. |
| Brand-domain matching | PASS curated scope | Seven classification states, exact/dot boundary matches, ambiguity handling and official product/country fixtures. |
| Typosquatting | PASS | Levenshtein, Jaro-Winkler and seven spelling pattern families, bounded inputs/outputs. |
| Homoglyph detection | PASS limited mapping | Selected Cyrillic/Greek fixtures; legitimate IDN does not automatically alert. Not complete Unicode TR39 or visual identity analysis. |
| Domain repurposing | LIMITED | Older-domain brand/form changes are contextual; compromise and ownership-transfer confirmation unavailable. |
| Email correlation | LIMITED | Optional supplied sender/reply-to domains and registry brand ID correlated with submitted URL/final page; no header authentication or full email link extraction. |
| Phase 6 integration | PASS | Single existing BRAND group, validated source/schema/scalars, no repeated page/history bonus; central verdict policy retained. |
| Phase 7 integration | PASS | Known plaintext reasons, actual source provenance, HISTORICAL category and bounded contextual reasons; no raw prompts. |
| Phase 8 integration | PASS | Reuse chain/final target; actual GitHub HTTP-to-HTTPS smoke; no repeated root fetch or JS execution. |
| Security | PASS scoped checks | SSRF/scope stops before contact, pinned public-IP/TLS transport, bounded JSON/HTML/JSON-LD, metadata/token redaction, privacy-safe history, unknown evidence failure handling. Bandit zero findings in changed runtime scope. |
| False-positive fixtures | PASS for brand evidence limits | Startup/new-domain, country/product domain, third-party sign-in, documentation/reseller, password-only, benign IDN and multi-brand fixtures. **End-to-end accuracy remains unvalidated; live PayPal is still a false alert.** |

## Tests and security verification

- Full suite: **536 passed, 0 failed, 0 errors**, 26 existing sklearn/SciPy deprecation warnings. These are regression/security fixtures, not an accuracy benchmark.
- Added 117 Phase 9 cases across tests/brand, tests/historical and tests/crawl.
- New Phase 9 runtime-module coverage: 93.78% (statement coverage; does not certify security or production performance).
- Fatal flake8 checks E9/F63/F7/F82 clean on new and changed runtime scope.
- Bandit: zero reported issues for new brand/JSON/RDAP code, risk/explanation adapters and changed fetch/registration/web/API/service modules. This is a scoped static check, not an independent security audit.
- Existing Phase 1–8 regressions and fixed model/data-contract checks passed. Original datasets and serving model artifacts were not changed in Phase 9.

Artifacts: reports/remediation_20261008/phase9_pytest.xml, phase9_coverage.json, phase9_bandit.json, phase9_performance.json, phase9_live_smoke.json and phase9_ui.jpg.

## Performance and actual runtime

Controlled measurements on this machine, with mock public transport, reused parser fixtures and the actual local serving model:

| Component | Iterations | Median ms | p95 ms |
|---|---:|---:|---:|
| inventory | 100 | 1.3847 | 1.5339 |
| similarity | 100 | 0.0154 | 0.0166 |
| rdap_normalization | 100 | 0.0073 | 0.0086 |
| brand_history_without_crawl | 100 | 0.8951 | 1.0317 |
| controlled_crawl | 100 | 3.4844 | 3.7460 |
| controlled_integrated_api | 10 | 167.8259 | 178.1926 |

p95 method: nearest lower order statistic. Traced peak Python allocation for ten sequential integrated fixture scans: 642,320 bytes. This excludes native allocations and total process RSS. All ten fixture API scans returned HTTP 200. These are not concurrent production load tests or network SLAs.

RDAP normalization timing is CPU-only. Individual WHOIS, external archive/CT/passive-DNS network latencies were not benchmarked; those providers were not used or are unavailable. Current DNS/TLS/RDAP network work is included in the live domain_ms values in the JSON artifact. History lookup/change work is included in the controlled brand/history timing. Existing Phase 8 concurrency/semaphore regressions passed, but sustained production load remains unvalidated.

Final-code live benign smoke, external elapsed time including HTTP/serialization overhead:

| Target | Registration source | Brand match | Final verdict | Elapsed ms | Crawl stop |
|---|---|---|---|---:|---|
| https://www.paypal.com/ | RDAP | OFFICIAL_SUBDOMAIN | SUSPICIOUS | 10924.4 | PAGE_OR_DEPTH_LIMIT |
| https://www.microsoft.com/ | RDAP | OFFICIAL_SUBDOMAIN | LEGITIMATE | 12491.3 | RESOURCE_LIMIT_EXCEEDED |
| http://github.com/ | RDAP | EXACT_MATCH | LEGITIMATE | 9202.1 | PAGE_OR_DEPTH_LIMIT |

All three returned HTTP 200, actual static HTML, explanation status OK, model schema 5.1.1 and 97 aggregate fields. The static crawl correctly returns PARTIAL on depth/page/time/resource boundaries rather than implying full-site inspection. Core defaults: four attempted pages, depth one, eight cumulative requests including root/robots/redirects, 2 MiB cumulative bytes, eight-second root-fetch-plus-crawl budget. Domain/model/serialization time is outside the crawl deadline.

The local development server was restarted with final code and debug disabled on localhost:5000. The browser form was exercised and the brand/history section visually inspected; screenshot saved in phase9_ui.jpg. This is a local development runtime, not a deployed production WSGI service.

## Created files

- app/brand: __init__.py, config.py, similarity.py, inventory.py, history.py, crawl.py, analyzer.py.
- app/security/json_fetch.py; app/risk/brand.py; utils/rdap_intelligence.py.
- config/brand_registry.json, brand_intelligence.json, brand_features.json.
- scripts/validate_brand.py and scripts/smoke_brand.py.
- tests/brand, tests/historical, tests/crawl package markers and test modules.
- The ten required docs: BRAND_INTELLIGENCE.md, BRAND_IMPERSONATION.md, TYPOSQUATTING.md, HISTORICAL_WEB_INTELLIGENCE.md, DOMAIN_TIMELINE.md, WEBSITE_AGE.md, PAGE_AGE.md, BRAND_EVIDENCE.md, DEEP_WEBSITE_INSPECTION.md, PHASE_09_REPORT.md.
- The verification artifacts listed above.

## Modified files

utils/registration_intelligence.py, domain_intelligence.py, html_features.py, web_intelligence.py, safe_fetch.py; app/__init__.py, api/v1.py, services/scans.py, behavior/privacy.py, risk/signals.py, risk/engine.py, risk/verdict.py, explanations/engine.py, explanations/reason_registry.py, templates/index.html; config/risk_scoring.json and explanations.json; README.md; docs/API.md, docs/FEATURE_SCHEMA.md, docs/DOMAIN_INTELLIGENCE.md, docs/EXPLAINABILITY.md; tests/risk/test_engine.py, tests/explanation/test_engine.py, tests/test_remediation.py. Existing dirty/untracked Phase 1–8 work was preserved.

Dependencies added: **none**. Existing urllib3, dnspython, BeautifulSoup, tldextract, WHOIS/parser, Flask and pytest tooling are reused; new code otherwise uses the Python standard library.

## Remaining issues and release limits

1. **Official PayPal still returns SUSPICIOUS** because the URL-only model assigns high probability to the observed final URL. Brand match does not override this estimate with a safety whitelist. Microsoft and GitHub returned LEGITIMATE. These three samples do not establish population accuracy.
2. Representative independent full-intelligence accuracy/confidence calibration remains pending from Phase 6. No detection accuracy percentage or public safety guarantee is claimed.
3. Curated registry coverage is limited to five brands and selected domains. Missing official country/product domains remain possible registry gaps. Homoglyph mapping is incomplete.
4. Archive, passive DNS, certificate transparency history, ownership history and ASN enrichment are unavailable. Process-local first_seen cannot establish historical website/page creation. Visual logo verification, OCR identity comparison and sitemap expansion are unavailable.
5. Email correlation is supplied-context only; authentication and full email URL analysis are not implemented. Dynamic browser behavior is still NOT_IMPLEMENTED and no Phase 10 media work was added.
6. Robots/body/time limits can leave child evidence incomplete. The scan is a bounded observation of inspected pages, not a guarantee about all routes or future content. Model confidence remains a provisional evidence-quality index.
7. Production concurrency/SLA, Redis-backed deployment configuration, external source quality and an independent security audit remain release work.

Recommended next step: resolve the remaining model false alert and validate on a representative independent full-pipeline evaluation before public launch. Phase 10 can be the next feature phase when requested; it will not itself repair or certify URL-model accuracy.

Scoring configuration SHA-256: `14c812dd796a24892721d13511511fcdbab908d6f389f9cbec17ab2bbab5a3b3`.
