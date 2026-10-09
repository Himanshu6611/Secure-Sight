# SECURESIGHT PHASE 8 COMPLETE — HTTP and static scope

Date: 2026-10-08. Behavior version **8.0.0**, scoring/assessment **6.1.0**, explanation **7.1.0**. Serving model/schema **5.1.1 unchanged**.

Completion covers verified HTTP redirects and static behavioral intelligence. **Dynamic browser isolation is NOT IMPLEMENTED.** This optional capability is disabled and cannot be enabled through configuration. This report does not certify public readiness or resolve the pending Phase 6 representative accuracy validation.

## Objective and inspection

Implemented bounded redirect chains, domain/scheme/destination transitions, loops, shortener context, static meta/JS navigation patterns, final-target correlation, safe redaction and integration into existing risk/explanation authorities. Inspected Phase 1–7 implementations and reports, actual risk/explanation schemas, existing pinned fetch/DNS/URL policy, public-suffix extraction, domain TTL cache, static DOM/script analysis, model contract and structured logging. No second HTTP fetcher, domain parser, ML detector or verdict engine was created.

## Architecture and implementation decisions

The existing safe fetcher manually observes HTTP 301/302/303/307/308 and records every header target. Each contacted hop revalidates public DNS and uses the existing literal-IP pinned pool with TLS hostname/certificate checks. Loops/default-port/fragment-normalized duplicate targets stop immediately. The shared gateway retains GET-only, no automatic redirects/retries, no forwarded cookies/authorization and cleanup in finally blocks.

Central behavior config allows five followed redirects, four-second request and six-second total retrieval budgets, 1 MiB final body and 16 static destinations. One boundary redirect header can be observed before the redirect-limit stop, so request/header count is at most six. Final bodies are bounded; compressed/non-HTML downloads are not accepted. Body limits do not claim a pre-allocation cap on all HTTP headers; underlying parser limits remain relevant.

Phase 4's existing parsed soup supplies literal meta-refresh targets/delays and JS location/replace/assign patterns. Existing obfuscation, forms, content and iframe intelligence are reused. New-window/challenge naming is static context only. No JS, target, decoded payload, authentication or CAPTCHA behavior is executed. No unsafe browser worker is created merely to claim dynamic completion.

The successfully reached final URL supplies lexical/model and domain intelligence. Existing Phase 3 cache is reused, with at most initial/final origin analysis rather than reputation requests at every intermediate hop. The final HTML is analyzed once, with no duplicate network fetch. Internal raw routing targets are removed at the public boundary.

## Evidence, privacy and versioning

Evidence retains phase_8 source, observed/inferred type, reason category/severity, observation confidence and numeric value. HTTP chain records distinguish observed target headers from destinations actually followed. Only successful final document retrieval supplies final_url; failed analysis supplies redacted last-attempted context. Domain-transition counts include observed cross-domain targets; unique-domain counts include actually observed response/document origins. Failure states remain explicit.

All new public URLs omit path/query/fragment values, including unknown query keys and path-carried tokens. Domain and structural change flags remain available. Existing web form/resource/canonical/favicon URL fields are redacted after analysis, and remote titles omitted. Raw URLs stay local to the scan; no redirect/body cache or scan persistence is introduced. Structured redirect logs contain request correlation, phase, status, duration, redirect/domain counts and error code, never destination query values or page text.

The separate config/behavior_features.json registry defines 11 versioned numeric/boolean fields for possible future ML use. None is passed to the current 97-field model vector. Behavior features do not imply that the current model learned redirect behavior. Old historical reports remain historical; they are not relabeled with Phase 8 accuracy/performance.

## Phase 6 and Phase 7 integration

Phase 8 generates evidence only. Phase 6 config 6.1.0 applies the strongest correlated redirect adjustment once: downgrade 10, loop 8, excessive chain 6 or domain hopping 4, bounded by a 10-point maximum and final score saturation. Ordinary cross-domain navigation, shortener use and HTTP-to-HTTPS add zero points. Contributions record actual effective points. Behavioral observations never count as an extra independent malicious source. Existing calibrated model/reliable reputation evidence may produce a correlated final-destination reason, not a fabricated new provider finding.

Incomplete redirect analysis and unexecuted static navigation targets gate definitive verdicts in the centralized Phase 6 policy. Completeness adds an optional redirect stage; weighted coverage/confidence still describe the original seven signal categories. Coefficients/confidence remain provisional, with no final-holdout tuning or retraining.

Phase 7 version 7.1.0 translates actual known behavior records using centralized wording, exposes zero-point context separately and preserves effective contributions. UI includes behavioral observations and an expandable redacted redirect chain. No new public API or persistent-ID endpoint was added.

## Verification

| Area | Result |
| --- | --- |
| Redirect engine | PASS |
| HTTP/static behavioral analysis | PASS |
| Meta/JS static redirect detection | PASS |
| Dynamic browser isolation | NOT IMPLEMENTED |
| SSRF controls | PASS in deterministic security tests |
| DNS rebinding / socket pinning | PASS in deterministic security tests |
| HTTP/static resource limits | PASS |
| Phase 6 integration | PASS |
| Phase 7/API/UI integration | PASS |
| Full automated suite | **419 passed, 0 failed**, 26 existing warnings |
| New redirect/behavior tests | **68 passed** |
| Phase 8 statement coverage | **92%** across behavior, gateway and risk adapter |
| Fatal lint | PASS |
| Bandit on behavior/gateway/risk adapter | **0 findings** |

Tests cover all five HTTP codes, scheme/domain/PSL transitions, loop/fragment/default identity, 1,000-header redirect bomb with bounded contact, private IPv4/IPv6/internal/metadata/file/javascript/nonstandard-port targets, public-to-private DNS rebinding, literal socket pinning, missing headers, DNS/timeout failures, huge Content-Length/stream bodies, compression/download rejection, deadline stop, query/path privacy, literal/static/obfuscated context, disabled browser execution, schema mismatch, non-fabricated evidence, contribution deduplication, final-target model compatibility and safe logging/public endpoints. No unit test depends on a live malicious website.

Deterministic fixtures: same_domain, cross_domain, loop, shortener, http_downgrade, excessive_chain and failed_redirect under tests/fixtures/redirect. Evidence logs/coverage/lint/Bandit are under reports/remediation_20261008/phase8_*.

## Performance and actual runtime

Controlled 100 redirect replays measured **0.169700 ms median / 0.200540 ms p95**. These use a deterministic pinned-gateway fixture, not Internet transport.

| Simultaneous clients | HTTP 200 | HTTP 503 | Accepted median / p95 ms |
| --- | --- | --- | --- |
| 1 | 1 | 0 | 165.591400 / 165.591400 |
| 10 | 2 | 8 | 309.903350 / 317.348645 |
| 50 | 2 | 48 | 575.415800 / 595.466270 |

Configured shared capacity is two. These results show bounded rejection under overload, not support for 50 simultaneously running analyses. Accepted/rejected timings are separate in the JSON report. Measured process CPU per load batch: 140.625/359.375/593.750 ms; peak Python allocations during load: **991,372 bytes**, excluding preloaded model/native/RSS memory. No process-memory isolation claim follows. Browser startup/analysis/queue time is null because no worker exists.

Latest real local API scans of benign GitHub targets returned HTTP 200 and ANALYZED behavior. `http://github.com/` observed a real 301 to HTTPS, used `https://github.com/` as analysis target and returned LEGITIMATE under current policy. Retrieval took about **1,854.66 ms** and total scan **5,292.29 ms** in that run; direct HTTPS total was **1,333.37 ms** with cached domain intelligence. These are single runtime observations, not an SLA or accuracy benchmark. The browser UI was exercised, its chain expanded and a screenshot saved.

Evidence: reports/phase8_20261008/validation_report.json, live_smoke.json and browser_result.png. Scoring configuration SHA256: **6ccc6f9d1f9880bedabfbae3ebb80963aba8136057acbf95ef776791b323c0b1**.

## Files created

- app/behavior/{__init__,config,privacy,evidence,static_redirects,analyzer}.py
- app/risk/behavior.py
- config/{behavior,behavior_reasons,behavior_features}.json
- tests/redirect and tests/behavior packages, 68 tests; seven tests/fixtures/redirect JSON fixtures
- scripts/validate_behavior.py; reports/phase8_20261008 runtime/load/preview evidence
- docs/{REDIRECT_ANALYSIS,BEHAVIORAL_ANALYSIS,REDIRECT_SECURITY,DYNAMIC_BROWSER_ANALYSIS,BEHAVIOR_FEATURES,PHASE_08_REPORT}.md

## Files modified

Existing safe_fetch, html_features and web_intelligence; scan service, app startup/API/log formatter/template; centralized risk config/schema adapter/engine; explanation config/registry/engine; version assertions in existing risk/explanation tests; explanation validation script's version metadata; README/API and historical-report version notes. Existing user changes were preserved.

Dependencies added: **none**. No model/schema vector change, retraining, final-test tuning, public deployment, commit, LLM execution or Phase 9 implementation occurred.

## Known issues and security limitations

Dynamic browser execution/isolation, worker lifecycle/exhaustion and runtime navigation/frame instrumentation are absent, not passed off as verified. Static JS patterns can be inactive or false alerts; client destinations are not resolved/executed and remain unknown. Obfuscation is not decoded or treated as proof of navigation. All redirect/body security tests use controlled transport; public hostile penetration testing and production container/network isolation were not performed. Capacity is two per worker in this development configuration.

The historical reputation false-alert concern and Phase 6 representative full-intelligence validation remain unresolved. New policy weights and overall confidence are provisional. Explanations and benign runtime checks do not guarantee detection accuracy. Production deployment/rate-store requirements still apply.

Recommended next implementation: **Phase 9 — Brand Impersonation & Typosquatting**, while separately completing outstanding representative accuracy/reputation validation before public readiness. Any future dynamic feature must first establish and verify a separate restricted worker environment.
