# SecureSight — ML Features

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Canonical Feature Registry

**Feature Schema Version:** `4.0`

The SecureSight Phase 5 model consumes a single deterministic feature vector of **57 numeric features** composed from three previous phases. Ordering is fixed in `ml/features.py` → constant `FEATURE_ORDER`, which is the single source of truth for:

- feature matrix column ordering
- preprocessor pickle validation
- inference feature alignment
- explainability permutation / SHAP feature indexing
- metadata stored in `models/v5/feature_schema.json`

All downstream code that consumes feature vectors MUST go through `ml.features.align_features_df(X)` which guarantees correct column order, adds missing columns filled with NaN, and drops unknown extras.

## 2. Feature Groups

### 2.1 Phase 2 — URL Intelligence (22 features)

Source extractor: `utils.url_features.extract_advanced_url_features`

| Index | Feature Name | Range | Type | Notes |
|---|---|---|---|---|
| 0 | `url_length` | ≥0 | int | Full URL character length |
| 1 | `hostname_length` | ≥0 | int | Hostname portion length |
| 2 | `path_length` | ≥0 | int | Path portion length |
| 3 | `query_length` | ≥0 | int | Query-string length |
| 4 | `fragment_length` | ≥0 | int | # fragment length |
| 5 | `digit_count` | ≥0 | int | Decimal-digit characters in URL |
| 6 | `special_character_count` | ≥0 | int | Non-alphanum count (excluding standard separators) |
| 7 | `hyphen_count` | ≥0 | int | Hyphen characters |
| 8 | `dot_count` | ≥0 | int | Dot characters (subdomain indicators) |
| 9 | `slash_count` | ≥0 | int | Forward-slash characters |
| 10 | `encoded_character_ratio` | [0,1] | float | Percent of characters percent-encoded |
| 11 | `entropy` | [0,8] | float | Shannon entropy on hostname/path |
| 12 | `subdomain_count` | ≥0 | int | Dots minus TLD part |
| 13 | `is_ip_host` | {0,1} | bool | Hostname parsed as IPv4/IPv6 literal |
| 14 | `punycode_detected` | {0,1} | bool | xn-- prefix present |
| 15 | `shortener_detected` | {0,1} | bool | Matches public URL-shortener domain list |
| 16 | `suspicious_token_count` | ≥0 | int | Keyword hits: login, verify, secure, account, update,… |
| 17 | `tld_risk_score` | [0,1] | float | Precomputed phishing-frequency per TLD |
| 18 | `has_port` | {0,1} | bool | Explicit port in URL (non-standard) |
| 19 | `at_symbol_present` | {0,1} | bool | `@` redirection indicator |
| 20 | `double_slash_redirect` | {0,1} | bool | `//` after scheme part (path-level redirect) |
| 21 | `sensitive_keyword_count` | ≥0 | int | Extended credential-theft keyword dictionary |

### 2.2 Phase 3 — Domain / DNS / TLS / Reputation (10 features)

Source extractor: `utils.domain_intelligence.analyze_domain_intelligence`

| Index | Feature Name | Range | Type | Notes |
|---|---|---|---|---|
| 22 | `domain_age_days` | ≥0 or 0 | int | WHOIS creation-date delta; 0 if unknown |
| 23 | `registrar_present` | {0,1} | bool | Registrar non-empty string → 1 |
| 24 | `dns_a_present` | {0,1} | bool | A record returned |
| 25 | `dns_aaaa_present` | {0,1} | bool | AAAA record returned |
| 26 | `dns_mx_present` | {0,1} | bool | MX record (mail exchanger) |
| 27 | `dns_ns_present` | {0,1} | bool | NS records present |
| 28 | `ip_reputation_score` | [0,1] | float | Aggregate blacklist/whitelist ratio |
| 29 | `domain_reputation_score` | [0,1] | float | Domain history + registrar trust score |
| 30 | `tls_valid` | {0,1} | bool | HTTPS handshake + valid leaf cert chain |
| 31 | `tls_expiry_days` | ≥0 or 0 | int | Days until leaf cert expiry; 0 if none |

### 2.3 Phase 4 — HTML / DOM / Structure (18 features)

Source extractor: `utils.web_intelligence.analyze_web_intelligence` → DOM block

| Index | Feature Name | Range | Type | Notes |
|---|---|---|---|---|
| 32 | `html_size` | ≥0 | int | Bytes of fetched HTML |
| 33 | `tag_count` | ≥0 | int | Parsed DOM tag count |
| 34 | `form_count` | ≥0 | int | `<form>` elements |
| 35 | `password_input_count` | ≥0 | int | `<input type=password>` count |
| 36 | `hidden_input_count` | ≥0 | int | `<input type=hidden>` count |
| 37 | `iframe_count` | ≥0 | int | `<iframe>` elements |
| 38 | `external_iframe_count` | ≥0 | int | Iframes with foreign-host src |
| 39 | `script_count` | ≥0 | int | `<script>` tags total |
| 40 | `inline_script_count` | ≥0 | int | Inline (non-src) scripts |
| 41 | `external_script_count` | ≥0 | int | Scripts loaded from src= |
| 42 | `external_domain_count` | ≥0 | int | Count unique external hosts referenced |
| 43 | `external_form_count` | ≥0 | int | Forms with action= to foreign host |
| 44 | `link_count` | ≥0 | int | `<a>` total |
| 45 | `external_link_count` | ≥0 | int | `<a>` pointing outside host |
| 46 | `hidden_element_count` | ≥0 | int | Elements with `display:none` or `visibility:hidden` |
| 47 | `obfuscated_script_count` | ≥0 | int | Scripts with `eval()` / long base64 / `charCodeAt` patterns |
| 48 | `canonical_domain_mismatch` | {0,1} | bool | `<link rel=canonical>` host ≠ page host |
| 49 | `favicon_domain_mismatch` | {0,1} | bool | `/favicon.ico` resolves to host ≠ page host |

### 2.4 Phase 4 — Content / NLP (7 features)

Source extractor: `utils.web_intelligence.analyze_web_intelligence` → NLP block

| Index | Feature Name | Range | Type | Notes |
|---|---|---|---|---|
| 50 | `login_language_score` | [0,1] | float | Lexical "login" / "sign-in" / "account" density |
| 51 | `urgency_score` | [0,1] | float | "Your account will be suspended" etc. |
| 52 | `credential_score` | [0,1] | float | "enter credentials" / re-verify / SSN patterns |
| 53 | `financial_language_score` | [0,1] | float | Bank / payment / card phrasing |
| 54 | `page_title_similarity` | [0,1] | float | Levenshtein-style match of `<title>` to known-brand DB |
| 55 | `brand_squat_score` | [0,1] | float | Levenshtein distance from hostname to known brands + TLD confusion |
| 56 | `oob_redirect_score` | [0,1] | float | `<meta refresh>` / JS redirect to external host pattern detection |

## 3. Missing-Feature Policy

- **Training** — preprocessing uses `sklearn.impute.SimpleImputer(strategy="median")` fit on the TRAIN split only. Imputer is persisted as part of `preprocessor.pkl` artifact.
- **Inference** — `ml.inference.SecureSightPredictor.predict(feature_dict, ...)` returns an `imputed_features` array listing every feature name that had to be filled with the stored median because it was missing / `None` in the supplied dict.
- **Unknown extras** — feature keys in `feature_dict` outside `FEATURE_ORDER` are DROPPED (with warning in debug mode, never raise).
- **Non-numeric / NaN / ±Inf** — causes `E002 INVALID_FEATURE_VECTOR` rejection. Never coerced, never silent SAFE.

## 4. Deterministic Ordering Contract

The `FEATURE_ORDER` list has the following invariants enforced by `tests/test_ml.py::TestFeatureSchema`:

1. It is a `list` (not a set / dict / tuple subclass).
2. It contains no duplicate strings.
3. Every item is a string `[a-z_]+` snake_case.
4. Every `align_features_df` call produces a DataFrame whose `list(df.columns) == FEATURE_ORDER` exactly, regardless of input column order / missing columns.
5. The list length is stable per major `FEATURE_SCHEMA_VERSION`; any addition bumps `FEATURE_SCHEMA_VERSION` and increments the model artifact folder.

## 5. Feature Schema Artifact

At the end of training, training.py writes:

```json
// models/v5/feature_schema.json
{
  "schema_version": "4.0",
  "features": [ "url_length", "hostname_length", ..., "oob_redirect_score" ],
  "count": 57,
  "groups": {
    "phase2_url": 22,
    "phase3_domain": 10,
    "phase4_dom": 18,
    "phase4_nlp": 7
  }
}
```

The `SecureSightPredictor.load()` method will refuse to load a model whose stored `feature_schema.json.features` differs from the `FEATURE_ORDER` compiled in the running codebase unless `strict_schema=False` (default: strict). This mismatch would return `E006 MODEL_SCHEMA_MISMATCH` and is never silently bypassed.
