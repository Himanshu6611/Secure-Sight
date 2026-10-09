# Advanced URL Feature Extraction & Intelligence Pipeline

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Pipeline Architecture

```text
               Raw Input URL
                     │
                     ▼
           URL Parsing & Evasion
           Normalisation Engine
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
     Lexical     Structural    Domain & TLD
    Features      Features       Features
        │            │            │
        ├────────────┼────────────┤
        ▼            ▼            ▼
    Protocol    Statistical   Suspicious
    Features     Entropy       Patterns
        │            │            │
        └────────────┼────────────┘
                     ▼
       Normalized Feature Vector (~62)
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
   Predictive ML             Rule-Based
  Ensemble Engine         Indicator Engine
 (Future Phase 5)       (Explainable Alerts)
```

---

## Analysis Stages

### Stage 1: Parsing & Evasion Normalization
1. **URL Scheme Normalization**: Ensures `http://` or `https://` prefix for reliable component splitting.
2. **Component Separation**: Parses URL into `scheme`, `hostname`, `port`, `path`, `query`, and `fragment`.
3. **Public Suffix & TLD Extraction**: Uses `tldextract` to separate `subdomain`, `domain`, and `suffix` (TLD).
4. **Authority & Evasion Checking**: Unpacks authority credentials (`userinfo@host`), hex encoding (`%XX`), and double-slash path obfuscation.

### Stage 2: Parallel Feature Extraction
Extracted across 6 specialized dimensions:
1. **Lexical Analysis**: Measures length metrics, special character frequencies, digit-to-letter ratios, and uppercase anomalies.
2. **Structural Hierarchy**: Quantifies subdomain depth, path tree depth, query parameter density, and fragment flags.
3. **Domain Intelligence**: Evaluates IP hostnames, known URL shorteners, high-risk TLDs, target brand keyword presence, and Levenshtein typosquatting distance.
4. **Protocol Audit**: Evaluates transport scheme (`https`), custom port definitions, and non-standard web ports.
5. **Information Theory & Entropy**: Calculates Shannon entropy across URL, domain, and path components to identify algorithmic generation or obfuscated payloads.
6. **Suspicious Pattern Scanning**: Counts phishing keywords, hex-encoded character sequences, and base64 query payloads.

### Stage 3: Explainable Risk Indicator Engine
Calculates aggregate risk scores (0–100) and maps findings to structured security indicators:
- `IP_AS_HOSTNAME`
- `URL_SHORTENER_DETECTED`
- `HIGH_RISK_TLD`
- `BRAND_IN_SUBDOMAIN` / `BRAND_IN_PATH`
- `TYPOSQUATTING_SUSPECTED`
- `EXCESSIVE_SUBDOMAINS`
- `HIGH_ENTROPY`
- `SUSPICIOUS_KEYWORDS`
- `AT_SYMBOL_OBFUSCATION`
- `EXCESSIVE_HEX_ENCODING`
- `NON_STANDARD_PORT`
- `DOUBLE_SLASH_IN_PATH`

---

## Future Integrations
The generated `features` vector is fully compatible with Phase 5 ML Ensemble retrain pipelines, enabling immediate training on multi-dimensional feature representations.
