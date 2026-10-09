# Cross-modal correlation

The graph links supplied email/website context → image identity → OCR/QR/provenance → extracted destination, and merges namespaced Phase 9 domain/page/brand/history graph nodes and edges. All image observations share the artifact SHA256 independence group. Normalized destinations are deduplicated; media does not rescore static page findings.

`RiskScoringEngine.assess_media` is the sole final risk policy: it carries an actual linked Phase 6 assessment with the current configuration digest; media adds zero unvalidated points. A linked LEGITIMATE website is downgraded to UNKNOWN for image authenticity. Image-only/missing/failed assessments remain UNKNOWN with null score. `ExplanationEngine.explain_media` uses six fixed known evidence IDs, verifies artifact identity and zero contribution, and returns a registry digest; it never invents model confidence.

Email sender/reply-to/brand context reuses Phase 9 validation and contextual comparisons. SPF, DKIM, DMARC, full MIME email parsing, BEC, sender history and campaigns are Phase 11 and are not implemented. Cross-modal media weights and calibrated authenticity confidence require evaluation before activation.
