# SecureSight — ML Architecture

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

**Document Version:** 1.0  
**Applicable Phase:** Phase 5 (Advanced ML Ensemble & Model Training)  
**Feature Schema Version:** `4.0`  
**Model Version:** `5.0.0`

---

## 1. Overview

SecureSight's ML subsystem transforms the deterministic URL/Domain/HTML/NLP intelligence
from Phases 2–4 into a calibrated, versioned, auditable binary phishing classifier.

The system intentionally prioritizes:

- **Leakage resistance** over single-run accuracy.
- **Reproducibility** via explicit seeds, hashes, and pinned versions.
- **Measurability** with 9+ security-relevant metrics (not just accuracy).
- **Explainability** with global (permutation/tree) and per-sample explanations.
- **Safety on failure**: a model error never silently returns "SAFE".

---

## 2. End-to-End Pipeline

```
Raw URL Dataset (CSV)
    │
    ├─► Dataset Validation (labels, schema)
    │
    ├─► Cleaning + URL normalization
    │
    ├─► Exact + registrable-domain duplication removal
    │
    ├─► Phase 2-4 Feature Engineering (URL/Domain/TLS/HTML/NLP)
    │         │
    │         ▼
    │   Canonical Feature Matrix (Parquet)
    │         │
    │         ▼
    │   Registrable-Domain Grouped Stratified Split
    │         │
    │         ├─► Training (≈70%)
    │         ├─► Validation (≈15%)
    │         └─► Test       (≈15%)  — untouched until final evaluation
    │
    ▼
Preprocessing Pipeline (per fold)
    │
    ├─►  Base Estimators
    │      ├─ Logistic Regression  (standardized, L-BFGS, class-weight balanced)
    │      ├─ Random Forest        (balanced class weights)
    │      └─ XGBoost / ExtraTrees (fallback if xgboost is unavailable)
    │
    ├─►  Cross-Validated OOF predictions (StratifiedKFold = 5)
    │
    ├─►  Ensemble Layer
    │      ├─ Soft Voting (weights = 0.2, 0.6, 0.2 as comparison baseline)
    │      └─ OOF Stacking (Meta-Learner: Logistic Regression)
    │
    ├─►  Probability Calibration (Isotonic regression on validation set)
    │
    ├─►  Threshold Selection (F1 / Recall / Precision priority, on val set)
    │
    ├─►  Final Evaluation (one-shot on untouched test set)
    │
    ▼
Versioned Artifact Package (models/v5/)
    ├─ model.pkl
    ├─ preprocessor.pkl
    ├─ feature_schema.json
    ├─ model_metadata.json
    ├─ threshold.json
    └─ metrics.json
```

---

## 3. Component Responsibilities

| Module | Purpose |
|:---|:---|
| [ml/dataset.py](file:///d:/capstone%20Project/ml/dataset.py) | Dataset loading, cleaning, registrable-domain extraction, and group-aware splitting. |
| [ml/features.py](file:///d:/capstone%20Project/ml/features.py) | Canonical 55-feature registry (`FEATURE_ORDER`) + versioned schema. |
| [ml/models.py](file:///d:/capstone%20Project/ml/models.py) | Per-estimator training + GridSearchCV / RandomizedSearchCV tuning. |
| [ml/ensemble.py](file:///d:/capstone%20Project/ml/ensemble.py) | OOF stacking ensemble with LR meta-learner. |
| [ml/calibration.py](file:///d:/capstone%20Project/ml/calibration.py) | Probability calibration (Platt/sigmoid or isotonic regression). |
| [ml/evaluation.py](file:///d:/capstone%20Project/ml/evaluation.py) | Metrics, threshold analysis, PR/ROC curves, permutation importance, and report serialization. |
| [ml/explainability.py](file:///d:/capstone%20Project/ml/explainability.py) | SHAP (optional) + permutation perturbation fallback for local per-sample explanations. |
| [ml/inference.py](file:///d:/capstone%20Project/ml/inference.py) | Production `SecureSightPredictor` with explicit error codes and local explanations. |
| [ml/training.py](file:///d:/capstone%20Project/ml/training.py) | Orchestrator: runs the entire pipeline, saves v5 artifacts and `reports/ml/*`. |
| [app/api/v1.py](file:///d:/capstone%20Project/app/api/v1.py#L89-L180) | `POST /api/v1/ml/predict` — schema-validated inference endpoint. |

---

## 4. Leakage Controls

| Control | Description | Spec Ref |
|:---|:---|:---|
| Registrable-Domain Group Split | URLs from the same registrable domain always land in the same train/val/test partition. | §9, §8 |
| Per-Fold Preprocessing | Imputers/Scalers are fit *inside* each cross-validation fold, never before. | §14, §20 |
| OOF Meta-Learner | Stacking trains on 5-fold out-of-fold predictions, not training-set predictions. | §28, §29 |
| Validation-Set Only Calibration | Isotonic/Platt is fit with `cv="prefit"` on the validation split. | §32 |
| Validation-Set Threshold Selection | Threshold is optimized on validation; test set is untouched until final evaluation. | §34, §47 |
| Deterministic Seeds | `RANDOM_STATE = 42` applied to all estimators, splits, and permutation scorers. | §41 |

---

## 5. Inference Contract

See Phase 5 §43 and [ml/inference.py](file:///d:/capstone%20Project/ml/inference.py).

**Happy path response:**
```json
{
  "status": "OK",
  "prediction": "phishing",
  "probability": 0.93,
  "threshold": 0.50,
  "model_version": "5.0.0",
  "feature_schema_version": "4.0",
  "latency_ms": 13.2,
  "explanations": [
    {"feature": "brand_domain_mismatch", "value": 1.0, "impact": "positive"},
    {"feature": "suspicious_token_count", "value": 4,   "impact": "positive"}
  ]
}
```

**Failure modes** (§45 — explicit, never silent "SAFE"):
- `MODEL_NOT_FOUND`
- `MODEL_VERSION_MISMATCH`
- `MODEL_LOAD_FAILED`
- `FEATURE_SCHEMA_MISMATCH`
- `INVALID_FEATURE_VECTOR`
- `MISSING_REQUIRED_FEATURE`
- `PREPROCESSING_FAILED`
- `PREDICTION_FAILED`

---

## 6. Model Selection Priority

Phase 5 §49 priority order (used to pick stacking vs voting, or threshold strategy):

1. Security-relevant **Recall** (minimize missed phish)
2. **False-Positive Rate** (minimize blocked legitimate sites)
3. **F1**
4. **PR-AUC**
5. **ROC-AUC**
6. **Accuracy**
7. Inference latency + memory footprint (performance benchmarking)

---

## 7. Versioning Contract

| Artifact | Schema | Example |
|:---|:---|:---|
| Model | SemVer 2.0 (MAJOR = incompatible API, MINOR = retrain, PATCH = fix) | `5.0.0` |
| Feature Schema | MAJOR.MINOR | `4.0` |
| Dataset Hash | SHA-256 per file | `0xabc…def` |
| Threshold + Calibration | Recorded in artifact JSON | `threshold = 0.42`, `method = isotonic` |

---

## 8. What This Architecture is NOT

- It is **not** the final SecureSight risk-score engine (that is Phase 6).
- It does **not** claim production readiness or 95%+ accuracy unless measured.
- It does **not** expose training endpoints via the public API.
