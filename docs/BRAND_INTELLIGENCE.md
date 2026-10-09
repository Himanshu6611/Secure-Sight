# Brand intelligence — Phase 9

The integrated URL scan returns `brand_intelligence` and `brand_feature_version: 9.0.0`. The existing 97-field ML schema and serving model remain 5.1.1; `config/brand_features.json` explicitly marks new features as unused by that model. Risk policy is 6.2.0 and explanation registry 7.2.0.

The pipeline reuses the final HTML and Phase 8 redirect destination. The existing DOM parser extracts bounded registry brand claims, fingerprints, counts and declared domains. A controlled crawl inspects additional same-host pages inside the final registrable site. Additional page claims contribute coverage and context, not repeated root risk points.

The curated registry covers PayPal, Microsoft, Google, GitHub and Apple, with aliases, selected official/product/country domains, source URLs, version and review date. It is deliberately incomplete. A domain absent from the registry is not automatically an impostor. Five brands do not constitute universal brand coverage.

`app/brand/analyzer.py` produces evidence only. Phase 6 owns every final score, severity, confidence and verdict. Historical, spelling and email context have zero additional score contributions. The existing BRAND group uses a corroborated Phase 9 mismatch instead of the old title-only heuristic during integrated scans. Standalone old feature endpoints retain their versioned model contract.

Default sources: live public pinned HTML, Phase 3 DNS/TLS/reputation, IANA-discovered RDAP with WHOIS fallback, and bounded process-local first observations. Web archives, passive DNS, certificate transparency history, ownership history, image/OCR identity verification and ASN enrichment are unavailable. These limitations are surfaced instead of inferred.

Tests: `tests/brand`, `tests/historical`, `tests/crawl`. Verification: `PHASE_09_REPORT.md`.
