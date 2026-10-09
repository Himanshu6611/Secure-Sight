# SecureSight — DOM & Form Intelligence Engine

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
The DOM & Form Intelligence engine inspects structural relationships between page origin, form submit destinations, password fields, hidden input elements, and embedded frames to detect credential harvesting and phishing traps.

## Form & Credential Analysis
- **Credential Form Detection:** Identifies forms containing password input fields or login terminology (`username`, `login`, `password`, `account`, `verify`).
- **External Form Action (`EXTERNAL_CREDENTIAL_FORM` / `EXTERNAL_FORM_DESTINATION`):** Triggered when a credential harvesting form submits data to a domain distinct from the page's registered domain.
- **Hidden Input Density:** Measures hidden fields commonly utilized by phishing kits to pass stolen session tokens or tracking parameters.

## Iframe Security
- **External Iframes (`EXTERNAL_IFRAME_DETECTED`):** Flags cross-origin embedded frames that may overlay fake login dialogs or trick users into credential entry.

## Domain Relationship Graph
Extracted cross-domain linkages:
```text
Page Origin Domain
  ├── Form Destination Domain -> (Cross-origin check)
  ├── External Script Domains -> (Obfuscation / CDN check)
  ├── Iframe Domains          -> (Embedding risk check)
  └── Favicon / Canonical     -> (Impersonation check)
```
