# Domain timeline and registration

The timeline distinguishes provider registration events (KNOWN_PROVIDER_EVENT), WEBSITE_FIRST_OBSERVED and PAGE_FIRST_OBSERVED (FIRST_OBSERVED), and fingerprint changes (OBSERVED_DIFFERENCE). Registration dates are not reused as website/page creation dates.

RDAP is primary. Discovery comes from the official IANA bootstrap registry at https://data.iana.org/rdap/dns.json, with a one-hour bounded process cache. Match the TLD, try up to two HTTPS service bases, then normalize a domain object whose ldhName matches the requested registrable domain. Registration results cache for at most one hour and retain original observed_at/retrieved_at; the existing domain intelligence cache remains five minutes.

Provider JSON uses the shared public-IP pinned outbound gateway: four-second overall RDAP deadline across discovery/service attempts, at most one manually validated redirect per JSON request, 128 KiB response limit, HTTPS verification, exact JSON media types, no compression, proxies, cookies, credentials, retries or automatic referrals. WHOIS fallback uses the existing IANA-to-registry public pinned port-43 gateway, six-second total deadline and 64 KiB response cap.

Normalized fields include created/updated/expiry events, days/months/years, registrar handle, statuses, nameservers, DNSSEC and source/retrieval metadata. Only registration events define age. Missing/future/invalid creation dates yield null age; updated/expiry dates cannot substitute. Expiration may legitimately be in the future. RDAP registrant vCards are discarded and owner status is UNKNOWN_OR_REDACTED. WHOIS metadata varies and is reported partially when unavailable.

Current A/AAAA/CNAME/MX/NS and TLS observations reuse Phase 3. Certificate issuance dates do not establish first website or page appearance. ASN enrichment and ownership history are unavailable.
