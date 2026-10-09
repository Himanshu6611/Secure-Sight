# URL Features Reference Guide

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
Phase 2 introduces SecureSight's **Advanced URL Feature Extraction Engine** (`utils/url_features.py`). The engine transforms any raw URL string into a fixed ~62 element numerical and boolean feature vector suitable for machine learning, real-time threat analysis, and rule-based heuristic scoring.

---

## Feature Groups & Categories

### 1. Lexical Features
Lexical features measure raw character distribution, string lengths, delimiter counts, and character ratios across the URL string.

| Feature Name | Type | Range | Description | Security Significance |
|--------------|------|-------|-------------|-----------------------|
| `url_len` | int | $[0, \infty)$ | Total character length of URL string | Phishing URLs often use extremely long paths or subdomains to obfuscate intent. |
| `hostname_len` | int | $[0, \infty)$ | Length of hostname/domain component | Long hostnames often hide payload destinations. |
| `path_len` | int | $[0, \infty)$ | Length of URL path component | Deep or obfuscated paths used in dynamic attack payloads. |
| `query_len` | int | $[0, \infty)$ | Length of URL query parameters string | Base64 payloads or target tracking parameters inside query strings. |
| `dot_count` | int | $[0, \infty)$ | Count of `.` characters | Excessive dots indicate deep subdomains or IP addresses. |
| `hyphen_count` | int | $[0, \infty)$ | Count of `-` characters | Hyphens frequently used in spoofed domain names (e.g. `paypal-security-login.com`). |
| `underscore_count` | int | $[0, \infty)$ | Count of `_` characters | Used in variable names and obscure path parameters. |
| `slash_count` | int | $[0, \infty)$ | Count of `/` characters | Path depth indicator. |
| `question_count` | int | $[0, \infty)$ | Count of `?` characters | Multiple `?` characters can confuse parsers. |
| `equal_count` | int | $[0, \infty)$ | Count of `=` characters | Key-value parameter density. |
| `at_count` | int | $[0, \infty)$ | Count of `@` characters | `@` symbol ignores authority prior to `@` and redirects browser. |
| `ampersand_count` | int | $[0, \infty)$ | Count of `&` characters | Query string multiplicity. |
| `percent_count` | int | $[0, \infty)$ | Count of `%` characters | Hex/URL encoding density. |
| `tilde_count` | int | $[0, \infty)$ | Count of `~` characters | User directory indicator on legacy web servers. |
| `digit_count` | int | $[0, \infty)$ | Number of numeric digits | High digit count indicates auto-generated domains or encoded IDs. |
| `letter_count` | int | $[0, \infty)$ | Number of alphabetic characters | Standard character baseline. |
| `uppercase_count` | int | $[0, \infty)$ | Number of uppercase letters | URLs are generally lowercase; uppercase mixed in domain/path indicates evasion. |
| `special_char_count` | int | $[0, \infty)$ | Non-alphanumeric character count | Obfuscation indicator. |
| `digit_ratio` | float | $[0.0, 1.0]$ | Proportion of digits in URL | Random DGA (Domain Generation Algorithm) detection. |
| `letter_ratio` | float | $[0.0, 1.0]$ | Proportion of letters in URL | Normal text ratio. |
| `uppercase_ratio` | float | $[0.0, 1.0]$ | Proportion of uppercase characters | Case evasion metric. |
| `special_ratio` | float | $[0.0, 1.0]$ | Proportion of special characters | Obfuscation density. |

---

### 2. Structural Features
Structural features evaluate the hierarchy and syntax of the parsed URL components.

| Feature Name | Type | Range | Description | Security Significance |
|--------------|------|-------|-------------|-----------------------|
| `subdomain_depth` | int | $[0, \infty)$ | Number of subdomain levels | $\ge 3$ subdomains frequently used to impersonate multi-tenant services. |
| `subdomain_len` | int | $[0, \infty)$ | Character length of subdomain string | Long subdomains used for brand spoofing (`login.paypal.account-verify.example.com`). |
| `path_depth` | int | $[0, \infty)$ | Depth of directories in path | Deep file hierarchies used to bury malicious scripts. |
| `query_params_count` | int | $[0, \infty)$ | Number of distinct query parameters | High parameter counts conceal tracking/redirect parameters. |
| `has_fragment` | bool/int | $\{0, 1\}$ | Flag indicating `#fragment` presence | Used in client-side routing and DOM-based XSS vectors. |
| `double_slash_in_path` | bool/int | $\{0, 1\}$ | Flag for `//` inside path | Open redirect indicator (`http://example.com//phishing.com`). |

---

### 3. Domain & Reputation Features
Domain features assess host identity, top-level domain abuse, brand spoofing, and typosquatting risk.

| Feature Name | Type | Range | Description | Security Significance |
|--------------|------|-------|-------------|-----------------------|
| `has_ip` | bool/int | $\{0, 1\}$ | Hostname is an IPv4 or Hex/Octal IP | Legitimate sites use registered domain names, not raw IPs. |
| `tld_len` | int | $[0, \infty)$ | Character length of TLD extension | Multi-part or long TLDs. |
| `is_suspicious_tld` | bool/int | $\{0, 1\}$ | TLD is in high-risk list (`.xyz`, `.top`, `.tk`, etc.) | High correlation with spam/malware domain registration. |
| `is_shortener` | bool/int | $\{0, 1\}$ | Domain is a known URL shortener (`bit.ly`, `tinyurl.com`, etc.) | Masks ultimate destination from manual inspection. |
| `brand_in_subdomain` | bool/int | $\{0, 1\}$ | Target brand keyword found in subdomain | Classic phishing trick (e.g. `paypal.com.attacker.com`). |
| `brand_in_path` | bool/int | $\{0, 1\}$ | Target brand keyword found in path | Phishing path spoofing (e.g. `attacker.com/paypal/login`). |
| `min_brand_distance` | int | $[-1, \infty)$ | Minimum Levenshtein distance to target brand list | Typosquatting detection (distance $\le 2$ indicates spoof attempt). |

---

### 4. Protocol Features
Protocol features verify network transport flags and port configuration.

| Feature Name | Type | Range | Description | Security Significance |
|--------------|------|-------|-------------|-----------------------|
| `has_scheme` | bool/int | $\{0, 1\}$ | Explicit protocol scheme present | Standard syntax check. |
| `is_https` | bool/int | $\{0, 1\}$ | Transport uses TLS (`https://`) | Plain HTTP is unencrypted; HTTPS phishing is also evaluated alongside certificate context. |
| `has_port` | bool/int | $\{0, 1\}$ | Explicit port number specified in URL | Non-standard port flag. |
| `is_non_standard_port` | bool/int | $\{0, 1\}$ | Port specified is neither 80 nor 443 | Malicious backdoors or non-web services (e.g. `:8080`, `:8443`, `:3128`). |

---

### 5. Statistical & Information Theory Features
Information theory metrics quantify character randomness and structural complexity.

| Feature Name | Type | Range | Description | Security Significance |
|--------------|------|-------|-------------|-----------------------|
| `url_entropy` | float | $[0.0, 8.0]$ | Shannon Entropy of entire URL string | Higher entropy ($> 4.5$) indicates randomized tokens or encrypted payloads. |
| `domain_entropy` | float | $[0.0, 8.0]$ | Shannon Entropy of domain hostname | Detects algorithmic DGA domains (`a8f9x2z1.com`). |
| `path_entropy` | float | $[0.0, 8.0]$ | Shannon Entropy of URL path | Detects obfuscated file names or path parameters. |

---

### 6. Suspicious Pattern Features
Pattern features scan for specific evasive techniques and high-risk keywords.

| Feature Name | Type | Range | Description | Security Significance |
|--------------|------|-------|-------------|-----------------------|
| `suspicious_keyword_count` | int | $[0, \infty)$ | Total count of phishing keywords in URL | Detects urgency and credential harvest terms (`login`, `verify`, `account`, `billing`). |
| `suspicious_kw_domain_count` | int | $[0, \infty)$ | Keyword count in hostname | Domain credential baiting. |
| `suspicious_kw_path_count` | int | $[0, \infty)$ | Keyword count in path | Path credential baiting. |
| `hex_encoding_count` | int | $[0, \infty)$ | Count of `%XX` hex-encoded characters | Obfuscation to bypass string matching filters. |
| `base64_strings_count` | int | $[0, \infty)$ | Detected Base64 pattern strings in query | Data exfiltration or encoded payload parameter. |
| `has_at_symbol` | bool/int | $\{0, 1\}$ | `@` symbol presence flag | Userinfo credential obfuscation exploit. |
| `consecutive_hyphens` | bool/int | $\{0, 1\}$ | `--` present in domain hostname | Punycode IDN spoofing or synthetic domain structure. |
