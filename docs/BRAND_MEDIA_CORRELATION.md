# Media brand correlation

OCR word-boundary matches reuse the existing curated Phase 9 registry. Results include observed brand IDs, optional email claimed brand, registry version and OCR_TEXT provenance. Extracted destination hostnames are compared using Phase 9 exact/official-subdomain boundaries and return an explicit domain relationship or UNMATCHED.

No visual logo matcher, embedding database or brand-template detector is installed: logo_match_confidence is null and logo_analysis_status is MODEL_UNAVAILABLE. A textual name, an official domain or a logo match cannot authenticate an image. UNMATCHED is contextual and contributes zero new media points; phishing corroboration belongs to the actual linked website's Phase 6 assessment.
