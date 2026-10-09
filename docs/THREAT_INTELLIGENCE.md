# Threat Intelligence Integration Guide

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Feature Schema Version 3.0
Phase 3 defines **Feature Schema Version 3.0**, unifying URL string metrics (Phase 2) with domain intelligence signals (Phase 3).

---

## Domain Feature Vector (`domain_features`)

The following numerical and boolean features are extracted for downstream ML ensemble consumption:

| Feature Key | Type | Description |
|-------------|------|-------------|
| `domain_age_days` | int | Domain age in days (-1 if unavailable) |
| `is_recent_registration` | int | 1 if domain age $\le 30$ days, else 0 |
| `dns_resolved` | int | 1 if DNS A/AAAA query succeeded, else 0 |
| `resolved_ip_count` | int | Total count of resolved IPv4 and IPv6 addresses |
| `has_private_ip` | int | 1 if domain resolved to private/loopback IP (SSRF risk), else 0 |
| `is_ssrf_safe` | int | 1 if domain resolves exclusively to public Internet IPs, else 0 |
| `tls_certificate_valid` | int | 1 if TLS cert is valid and trusted, else 0 |
| `tls_days_until_expiry` | int | Days remaining before SSL cert expires (-1 if unavailable) |
| `is_blacklisted` | int | 1 if domain appears in threat intelligence blacklists, else 0 |
