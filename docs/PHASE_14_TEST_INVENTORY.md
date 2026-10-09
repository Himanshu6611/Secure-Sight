# Phase 14 executed test inventory

Executed 2026-10-09 on Windows; 859 tests, 0 failures/errors, 0 skips. Historical pre-remediation baseline: 731 passed. Evidence: `reports/phase14_20261009/`; commands/logs and JUnit are retained.

Counts are parametrized JUnit cases by module, not inflated claims of separate testing layers. Modules overlap layers; there is no honest single numerical pyramid.

| Module | Executed cases |
|---|---:|
| tests.behavior.test_behavior | 29 |
| tests.brand.test_intelligence | 71 |
| tests.crawl.test_crawl | 22 |
| tests.explanation.test_engine | 50 |
| tests.historical.test_history | 25 |
| tests.redirect.test_redirects | 39 |
| tests.risk.test_engine | 84 |
| tests.test_domain_intelligence.TestCache | 1 |
| tests.test_domain_intelligence.TestDNSAndSSRF | 5 |
| tests.test_domain_intelligence.TestDomainExtraction | 3 |
| tests.test_domain_intelligence.TestDomainIntelligenceAPI | 2 |
| tests.test_domain_intelligence.TestDomainIntelligenceService | 1 |
| tests.test_domain_intelligence.TestRegistrationIntelligence | 1 |
| tests.test_domain_intelligence.TestReputationProviders | 2 |
| tests.test_domain_intelligence.TestTLSIntelligence | 2 |
| tests.test_email_documents | 8 |
| tests.test_email_training | 16 |
| tests.test_images_and_reputation | 9 |
| tests.test_ml.TestCalibration | 2 |
| tests.test_ml.TestDatasetIntegrity | 7 |
| tests.test_ml.TestEvaluationMetrics | 5 |
| tests.test_ml.TestExplainability | 2 |
| tests.test_ml.TestFeatureSchema | 6 |
| tests.test_ml.TestInference | 5 |
| tests.test_ml.TestRegressionFixtures | 6 |
| tests.test_ml.TestStackingEnsemble | 3 |
| tests.test_phase10_media | 47 |
| tests.test_phase11_email | 54 |
| tests.test_phase12_dashboard | 51 |
| tests.test_phase13_security | 46 |
| tests.test_phase14_quality | 26 |
| tests.test_phase15_adversarial | 39 |
| tests.test_phase16_seo | 19 |
| tests.test_phase17_performance | 5 |
| tests.test_remediation | 39 |
| tests.test_routes | 10 |
| tests.test_runtime_secrets | 8 |
| tests.test_security | 79 |
| tests.test_url_features.TestAPIEndpoint | 2 |
| tests.test_url_features.TestURLFeatures | 10 |
| tests.test_url_features.TestURLIndicators | 3 |
| tests.test_utils | 2 |
| tests.test_web_intelligence.TestContentNLP | 2 |
| tests.test_web_intelligence.TestDynamicAnalysisIsolation | 1 |
| tests.test_web_intelligence.TestHTMLAndDOMAnalysis | 4 |
| tests.test_web_intelligence.TestSafeFetchGateway | 4 |
| tests.test_web_intelligence.TestWebIntelligenceOrchestration | 2 |

Unit/metamorphic: URL features, normalization, risk, gate integrity, leakage adversaries, historical observations. Integration: pinned fetch/DNS, provider circuits, encrypted SQLite, worker isolation, OCR/QR, signed C2PA and email authentication. API/security: error/schema/status contracts, auth/CSRF/tenant isolation, exports, poisoned JSON, upload bounds, SSRF and rate limits. Workflow integration: URL/domain/web/brand/risk/explanation fixtures; email URL/image correlation; media evidence; dashboard evidence/graph/timeline/export. These mocked or in-process workflows are not a live provider or production browser E2E certification.

Frontend: seven local Playwright/axe browser E2E tests passed with no failures, flakes or skips. Coverage includes public routes, all three scanner modes, keyboard and focus, form labels/errors/loading/result announcements, upload validation, WCAG 2.1 A/AA automated checks and mobile layout. JSON and HTML reports are retained under `reports/phase14_20261009/` and `web/playwright-report/`. This does not replace manual assistive-technology testing or live provider/production certification. Optional neural deepfake model and labeled real-world genuine/manipulated image benchmarks are UNAVAILABLE; media tests verify explicit unavailable/unknown states, synthetic forensic and real OCR/QR/C2PA fixtures. No accuracy claim for deepfake detection.

Conditional skips exist for missing v5 artifacts and non-Windows Job integration. This execution has zero skips. Required gates reject any unapproved skip. No blanket retry, xfail or flaky-test waiver was added. No observed flaky failure in these runs; this does not establish absence of flakes.
