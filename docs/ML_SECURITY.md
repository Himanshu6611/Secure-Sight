# SecureSight — ML Security

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Threat Model (§43 Inference Contract & §51 Endpoint)

The ML subsystem exposes:

- **Inference interface:** file system-boundary: unprivileged user sends JSON → Flask → SecureSightPredictor.

Attack surface:

1. Network inputs `POST /api/v1/ml/predict` — arbitrary JSON feature dict.
2. Pickle artifact loading: `models/v5/model.pkl` + `preprocessor.pkl`.
3. Metadata files loaded from disk at model version folders (JSON/
4. Edge case: `strict_version=True rejects in ` / sklearn version mismatches.
5. Data poisoning: upstream data sources (`raw/cleaned CSV) consumed at training time.

## 2. Input Validation at Endpoint

Handler `app/api/v1.py::ml_predict_endpoint`:

- Require `Content-Type: application/json` — `flask.Request.is_json` is checked first; non-JSON requests are rejected with HTTP 400 `INVALID_JSON_BODY.
- `Request body MUST contain a `features` key pointing to a JSON object (dict). Missing dict raises MISSING_FEATURES error code.
- Each feature value MUST be convertible to numeric; booleans, integers, floats accepted.
- Unknown feature keys NOT in canonical order; accepted then DROPPED silently (never raises). never — these will appear in predictor's output list; never sent back.
- Request- never returns SAFE/legitimate on any failure: §45

### 45 Error Codes

Every HTTP mapping

| §45 Code | HTTP | Meaning |
|---|---|---|
| `MODEL_NOT_FOUND` | 503 | model v5 not present / artifacts missing. |
| `MODEL_VERSION_MISMATCH` | 503 | `strict_version=True and runtime version / sklearn version / |
| `MODEL_LOAD_FAILED` | 500 | Pickle / metadata I/O or deserialization raised; transient. |
| `FEATURE_SCHEMA_MISMATCH` | 500 | Artifact schema vs code schema differ; not a user-input problem. |
| `INVALID_FEATURE_VECTOR` | 400 | Feature dict contains non-numeric / NaN / ±Inf values. User-data. |
| `MISSING_REQUIRED_FEATURE` | 400 | Critical features missing. (Currently unused; all features are median-imputed and reported in `imputed_features` list.) |
| `PREPROCESSING_FAILED` | 500 | Preprocessing step raised (rare — runtime bug. |
| `PREDICTION_FAILED` | 500 | Estimator `.predict_proba` raised; includes cases — treated as runtime failure, return predictions. |

## 3. Deserialization Security

### 3.1 Pickle Threats

`joblib.load` is known arbitrary code execution: arbitrary code execution**
- `.n
- `joblib.load model was the: is 2004.

Mitigations:

1. Load only from `models/v5/` (restricted disk location.
2. Never load a pickle from user-supplied input — the endpoint never untrusted bytes.
3. Integrity chain of custody: v5 artifacts only written by `python -m ml.training` during CI CD pipeline; CI signs on on
4. File permissions: `models/v5/*.pkl` recommended `chmod 0644` readable, owned by service account; Flask user.

### 3.2 JSON Artifact Validation

`load()` 2 JSON parsed from disk with:

```json
feature_schema.json  → schema version, 57 features.
model_metadata.json → required fields are is not a dict → MODEL_LOAD_FAILED
threshold.json      → "threshold" key parsed to float
```

Missing keys are handled via `.get( with defaults; malformed JSON raises an exception and the load() method catches wraps it.

## 4. Data Poisoning & Leakage Controls (training)

### 4.1 Domain-grouped split
- Critical leakage; domains disjoint  cross split — per registrable domain. invariant.
split. -group,
.registrable domain grouping.
registrable domain. never train. splits.
### 4.2 Preprocessor fit on TRAIN split only
Impute+Scaler fit only fit val/test split — impute median values from the training set only.
### 4.3 Calibration & threshold fit on VALIDATION set.
Isotonic regression calibrator + threshold sweep + 81-point sweep calibrated probabilities split 4.4 Test test set untouched.
Until, used once, final evaluation. No decisions using test data.
### 4.5 Deterministic seeds
42 seeds all splits, 42 5. Rate Limiting & per second.
See docs/SECURITY.md for the repository-wide rate limiting / auth config. The `/api/v1/ml/predict` endpoint shares the same Flask before-after request. as other rate limiter.
6. Endpoint Request
Endpoint` 045 §6.

| Error Payloads.
7. Transparency & No Silent Failures.
Every failure returns `status`, `error_code`, and `detail`.
8. Dependency & Vulnerability.
See docs/DEPENDENCY_AUDIT.md.

Always ML-related dependencies sklearn, scipy, numpy, joblib, pandas) have been scanned via.
9. Phase Phase §). No
`X model training phase not browser extension, email scanner, offensive security, XSS scanner.
