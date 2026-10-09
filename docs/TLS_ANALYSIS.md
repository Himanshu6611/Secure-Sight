# TLS/SSL Certificate Analysis Guide

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
The TLS Inspection module (`utils/tls_intelligence.py`) connects to HTTPS services over SSL/TLS sockets with strict 2.0s timeouts to inspect certificate integrity and validity.

---

## Certificate Statuses

- `VALID`: Certificate is present, trusted, valid, and has $> 14$ days remaining before expiration.
- `EXPIRING_SOON`: Certificate is valid but expires within 14 days.
- `EXPIRED`: Certificate expiration date (`notAfter`) is in the past.
- `INVALID`: Handshake failed due to certificate verification error (hostname mismatch, untrusted issuer, self-signed).
- `UNAVAILABLE`: Target does not use HTTPS, connection timed out, or connection refused.

---

## Extracted Certificate Metadata
- `certificate_present` (bool)
- `certificate_valid` (bool)
- `days_until_expiry` (int)
- `issuer` (dict containing CN, O, OU)
- `subject` (dict containing CN, O, OU)
- `not_before` (ISO string)
- `not_after` (ISO string)
