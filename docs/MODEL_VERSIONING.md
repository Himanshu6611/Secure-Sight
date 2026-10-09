# SecureSight — Model Versioning

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Versioning Scheme

SecureSight model artifacts follow a **semver-like model_version + parallel directory** scheme:

```text
models/
├── v1/   (legacy — Phase 1-4 — not used by Phase 5 code)
├── v2/   (future — reserved)
├── v3/   (future — reserved)
├── v4/   (future — reserved)
└── v5/   ← CURRENT Phase 5 model artifacts
```

Within a single folder `vX/` stores **all** necessary artifacts; consumers of a model version. A model_version `"5.0.0"` (semver) is stored in `models/v5/` — the folder digit is the major version. No artifacts are scattered elsewhere.

## 2. Artifact Manifest

Every model version folder is self-contained. It must contain exactly the following six files (no more, no fewer, with zero missing).

| File | Format | Purpose |
|---|---|---|
| `model.pkl` | joblib pickle | Calibrated final ensemble. `joblib.load`able sklearn-compatible estimator, with `.predict_proba(X)` method. |
| `preprocessor.pkl` | joblib pickle | Pipeline of `[SimpleImputer, StandardScaler] fit on TRAIN split. |
| `feature_schema.json` | JSON | Schema version, ordered feature list, feature count. |
| `model_metadata.json` | JSON | Full reproducibility record. |
| `threshold.json` | JSON | Operating threshold + selection priority + validation metrics at that threshold. |
| `metrics.json` | JSON | Final holdout test-set metrics snapshot (for Phase 6 quick lookup). |

The inference wrapper `SecureSightPredictor` is hard-codes `V5_MODEL_DIR = models/v5`; ALLOWED_MODEL_VERSIONS = {"5.0.0", "5.0", "5"}`. To release a v5.x, bump the folder prefix and update the list.

## 3. Model & Feature Schema Versioning

Two orthogonal versions track separate axes:

- `model_version` (semver, in `model_metadata.json`):
  - `MAJOR` — incompatible artifact layout changes (e.g. new ensemble type)
  - `MINOR` — backwards-compatible performance improvements (e.g. more data, retrain)
  - `PATCH` — backwards-compatible bug fixes (e.g. label mapping, no model change)

- `feature_schema_version` (string, in `feature_schema.json` and `ml/features.py::FEATURE_SCHEMA_VERSION`):
  tracks the feature list ordering / additions breakage contract is binding at `ML_MM breakage of feature list. Rule: `feature_schema_version` bump is bumped always forward/backward compatible versioning:

### Version Compatibility Matrix

| feature_schema_version of artifact ↓ / code FEATURE_SCHEMA_VERSION → | 3.0 (old) | 4.0 (current) | 5.0 (future) |
|---|---|---|---|
| 4.0 | mismatch ❌ | match ✅ strict_schema=True | mismatch ❌ |
| 3.0 | match ✅ `strict_schema=False (deprecated; not supported in v5 | mismatch ❌ |

## 4. Strict Version Gate

The `SecureSightPredictor.__init__(model_dir, strict_version=False)` has two toggles:

| Toggle | Default | Effect |
|---|---|---|
| `strict_version` | `False` | `True` then the predictor refuses to load models whose Python / sklearn version are different from training |
| strict_schema ` (implicit, via feature order mismatch when artifact feature_schema.feature_order != code `FEATURE_ORDER` hard-fail; raises `FEATURE_SCHEMA_MISMATCH` status.

### Loading sequence:

1. Load model joblib
2. Read metadata
3. If `strict_version` & metadata.python metadata.model_version is not in ALLOWED_MODEL_VERSIONS OR doesn't start with v prefix → `MODEL_VERSION_MISMATCH`
4. Read feature schema
5. If artifact feature order != code `FEATURE_ORDER` → `FEATURE_SCHEMA_MISMATCH`
6. Read threshold
7. Load preprocessor (if preprocessor.pkl exists)
8. Ready.

## 5. Provenance Chain

Every `model_metadata.json` under stores sufficient information to reproduce the training run, even years later. It includes:

```json
{
  "model_version": "5.0.0",
  "feature_schema_version": "4.0",
  "model_type": "calibrated_stacking_ensemble",
  "training_date": "<ISO-8601>",
  "random_seed": 42,
  "cv_folds": 5,
  "split_strategy": "domain_grouped_stratified_70_15_15",
  "threshold": 0.5,
  "threshold_selection": { ... },
  "calibration": { "method": "isotonic", "report": { ... } },
  "environment": {
    "python_version": "3.12.10 (...)",
    "scikit_learn_version": "1.6.1"
  },
  "dataset": {
    "provenance_hash": { /* see dataset_hash.json */ },
    "n_features": 57,
    "feature_names": [ "url_length", "hostname_length", ... ]
  },
  "test_metrics": { /* full test-set metrics snapshot */ }
}
```

Additionally, the upstream data files `data/metadata/dataset_hash.json` and `data/metadata/dataset_manifest.json` are considered immutable inputs to the provenance chain.

## 6. Promotion Workflow

When a new model version is trained (e.g. 5.1.0):

1. Create `models/v5_new/` directory alongside current `models/v5/`.
2. Run `python -m ml.training`, pointed at new (or updated) dataset.
3. Verify `reports/ml/` outputs all expected files and test-set F1 ≥ previous model F1 − 0.02 tolerance.
4. Smoke-test the Flask endpoint via the test-client test.
5. Swap atomically: remove `models/v5/` backup and copy new dir -> `models/v5/`.
6. Update `ALLOWED_MODEL_VERSIONS` set in inference if and only if the major version changed.
7. Restart the Flask app server so `current_app.extensions["ml_predictor"]` lazy-loads the new artifacts on next request.

## 7. Rollback

Because versions are folder-siloed, rollback is simply: swap `models/v5/` back to the previous snapshot and restart the server. The codebase never reads `models/ensemble.pkl` (legacy Phase 1-4 voting) when serving `/api/v1/ml/predict` — they live isolated.

## 8. Pickle Security

See `docs/ML_SECURITY.md` § Pickle deserialization attack surface and remediation.
