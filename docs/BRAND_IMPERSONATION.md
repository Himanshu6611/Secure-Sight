# Brand impersonation

Brand claims come from title, headings, selected descriptive/Open Graph metadata, visible body text, logo alt text, form labels/buttons and bounded JSON-LD Organization/Corporation/Brand names. Only trusted registry IDs and canonical names leave the parser. Raw text, instructions, contact details and arbitrary JSON-LD are not copied into explanations.

The title is excluded from visible-body text, so a title alone does not become two sources. Sources on one page remain correlated under STATIC_PAGE. Multiple brands with equally strong claims remain ambiguous unless the official hostname resolves the tie.

Classifications: EXACT_MATCH, OFFICIAL_SUBDOMAIN, KNOWN_OFFICIAL_DOMAIN, POSSIBLE_MATCH, LOOKALIKE, MISMATCH, UNKNOWN. Host matches require an exact name or a dot-delimited official suffix. `paypal.com.evil.example` and `notpaypal.com` cannot match paypal.com. PSL private suffixes are retained; tenant GitHub Pages domains are not registered as official GitHub subdomains.

Scored brand mismatch requires multiple page fields including an identity field, a password input and either nonofficial external credential collection or a close spelling/confusable match. A known official credential destination prevents spelling-only corroboration. Domain age, logo text, HTTPS, missing contact text, redesign and third-party sign-in do not alone prove impersonation. Unverified external credential collection still prevents a legitimate verdict under central Phase 6 policy.

An official domain match is contextual and never a safety whitelist. Live PayPal smoke still yielded SUSPICIOUS because the existing URL model overestimated risk; this is an unresolved public-release limitation.
