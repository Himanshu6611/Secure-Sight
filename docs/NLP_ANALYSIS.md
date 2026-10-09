# SecureSight — Content NLP Analysis Engine

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
The Content NLP engine (`utils/content_nlp.py`) evaluates webpage text against externalized phishing keyword dictionaries (`config/phishing_keywords.json`) to compute normalized intent scores (0.0 to 1.0) and detect brand impersonation.

## Keyword Categories & Dictionaries
Keywords are stored externally in `config/phishing_keywords.json`:
- **`authentication`**: `["login", "signin", "password", "verify account"]`
- **`urgency`**: `["immediately", "urgent", "account suspended", "warning"]`
- **`financial`**: `["payment", "billing", "credit card", "bank"]`
- **`credential`**: `["enter password", "confirm password", "otp", "pin"]`
- **`security`**: `["security alert", "unauthorized access", "verification"]`

## Normalized Feature Scores
- `login_language_score`: Min(1.0, authentication_hits / 3.0)
- `urgency_score`: Min(1.0, urgency_hits / 2.0)
- `financial_language_score`: Min(1.0, financial_hits / 2.0)
- `credential_score`: Min(1.0, credential_hits / 2.0)
- `security_language_score`: Min(1.0, security_hits / 2.0)
- `phishing_keyword_count`: Total sum of hits across categories.

## Brand Impersonation Signal (`BRAND_DOMAIN_MISMATCH`)
- Compares brand names mentioned in page titles/headings against `TARGET_BRANDS`.
- If a target brand (e.g. `microsoft`, `paypal`, `chase`) is claimed in text/title but the domain is not an official domain of that brand, `brand_domain_mismatch = 1` is generated.
