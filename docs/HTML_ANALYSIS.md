# SecureSight — HTML Structure Analysis Engine

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
The HTML Structure Analysis module (`utils/html_features.py`) performs static parsing and structural feature extraction on remote webpage HTML snapshots.

## Key Extraction Features
- `html_size`: Total byte size of HTML content.
- `tag_count`: Total count of DOM element tags.
- `form_count`: Total `<form>` elements detected.
- `password_input_count`: Total `<input type="password">` fields.
- `hidden_input_count`: Total `<input type="hidden">` fields.
- `iframe_count`: Total embedded `<iframe>` elements.
- `external_iframe_count`: Count of `<iframe>` elements pointing to third-party domains.
- `script_count`: Total `<script>` elements.
- `inline_script_count`: Count of inline `<script>` blocks.
- `external_script_count`: Count of external `<script src="...">` loads.
- `external_domain_count`: Unique third-party registrable domains referenced across resources.
- `external_form_count`: Forms submitting data cross-origin (`action="http://other.com"`).
- `link_count`: Total hyperlink `<a href="...">` tags.
- `external_link_count`: Count of external hyperlinks pointing off-domain.
- `hidden_element_count`: Elements with `display:none`, `visibility:hidden`, or `hidden` attribute.
- `obfuscated_script_count`: Inline scripts matching JS obfuscation regex patterns (`eval(`, `Function(`, `atob(`, `unescape(`, `\x..`, `\u..`).
- `canonical_domain_mismatch`: Binary flag indicating if `<link rel="canonical">` points to an external domain.
- `favicon_domain_mismatch`: Binary flag indicating if `<link rel="icon">` points to an external domain.

## Safety & Parsing Contract
- Uses BeautifulSoup DOM parser safely without executing arbitrary JavaScript code.
- Gracefully parses broken, malformed, or unclosed HTML tags without crashing.
