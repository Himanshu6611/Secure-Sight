# Domain Intelligence Architecture & Specification

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
Phase 3 introduces SecureSight's **Domain & Reputation Intelligence Engine** (`utils/domain_intelligence.py`), extending URL security analysis from raw string character inspection to external domain, DNS, TLS/SSL, registration age (WHOIS), IP range classification, and multi-provider reputation lookup.

---

## Service Architecture

```text
                           Raw Input URL
                                │
                                ▼
                    Phase 2 URL Feature Engine
                                │
                                ▼
                    Domain Components Extractor
                   (IDN / Punycode / Public Suffix)
                                │
       ┌────────────────────────┼────────────────────────┐
       ▼                        ▼                        ▼
  DNS Resolution            TLS/SSL Audit            WHOIS Registration
 (A, AAAA, IP Class)      (Handshake & Cert)       (Creation & Age Days)
       │                        │                        │
       └────────────────────────┼────────────────────────┘
                                ▼
                    Multi-Provider Reputation
                   (Local + External Threat API)
                                │
                                ▼
                     Unified Domain Payload
                     (Feature Version 3.0)
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
      Domain Feature Vector               Security Evidence
      (ML Ensemble Signals)              (Explainable Indicators)
```

---

## Key Modules

| Module Name | Path | Purpose |
|-------------|------|---------|
| Domain Extraction | `utils/domain_extraction.py` | Public-suffix aware domain parsing, Punycode IDN conversion, trailing dot stripping |
| DNS Intelligence | `utils/dns_intelligence.py` | Controlled DNS lookup, A/AAAA record extraction, IP range classification, SSRF protection |
| TLS/SSL Intelligence | `utils/tls_intelligence.py` | TLS certificate inspection, issuer/subject extraction, expiration calculation |
| Registration Intelligence | `utils/registration_intelligence.py` | WHOIS lookup, creation date parsing, domain age in days |
| Reputation Provider Layer | `utils/reputation_providers.py` | Provider abstraction, CSV blacklist provider, External API skeleton, MultiProviderAggregator |
| TTL Memory Cache | `utils/domain_cache.py` | Thread-safe memory cache preventing duplicate external network lookups |
| Unified Service | `utils/domain_intelligence.py` | Unified service producing version `3.0` domain features and explainable security indicators |

## Phase 9 current behavior

Current Phase 9 registration lookup is RDAP-first with IANA discovery and public-IP pinned JSON, then existing bounded WHOIS fallback. Provider creation dates define domain age; local website/page first_seen are separate and cannot establish creation. See DOMAIN_TIMELINE.md and PHASE_09_REPORT.md for verified scope and unavailable history providers.
