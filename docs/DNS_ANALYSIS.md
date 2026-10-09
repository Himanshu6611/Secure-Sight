# DNS Analysis & IP SSRF Safety Guide

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
The DNS Analysis module (`utils/dns_intelligence.py`) provides controlled DNS lookup, IP range classification, and SSRF (Server-Side Request Forgery) protection.

---

## IP Range Classification
Resolved IP addresses are evaluated against standard IP networks using Python's `ipaddress` module:

| Category | Definition / IP Subnet | Security Impact |
|----------|------------------------|-----------------|
| `PUBLIC` | Globally routable Internet IPs | Standard web traffic destination |
| `PRIVATE` | RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) | SSRF vulnerability target |
| `LOOPBACK` | `127.0.0.0/8`, `::1/128` | Localhost exploit target |
| `LINK_LOCAL` | `169.254.0.0/16`, `fe80::/10` | Cloud metadata service exploit target (e.g. AWS `169.254.169.254`) |
| `MULTICAST` | `224.0.0.0/4` | Non-standard destination |
| `INVALID` | Malformed IP string | Parsing error |

---

## SSRF Validation
`is_ssrf_safe_ip(ip)` returns `True` **only** if the target IP resolves to a `PUBLIC` IP address. Any domain resolving to `PRIVATE`, `LOOPBACK`, `LINK_LOCAL`, or `MULTICAST` addresses is marked `has_private_ip: True` and flagged with security indicator `PRIVATE_IP_RESOLVED`.

---

## Controlled DNS Failure Classification
DNS resolution handles timeouts and network exceptions gracefully, classifying outcomes into discrete failure statuses:
- `SUCCESS`
- `DOMAIN_NOT_FOUND`
- `DNS_TIMEOUT`
- `DNS_PROVIDER_ERROR`
- `INVALID_DOMAIN`
