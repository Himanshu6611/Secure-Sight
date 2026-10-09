# SecureSight — Phase 5 — Advanced ML Ensemble & Model Training

**Project:** SecureSight  
**Phase:** 5 of 19  
**Previous Phases:** Phase 1 Architecture & Security Foundation, Phase 2 URL Intelligence, Phase 3 Domain & Reputation Intelligence, Phase 4 HTML/DOM & Content Intelligence  
**Next Phase:** Phase 6 — Risk Scoring & Confidence Engine

---

## 1. Phase Objective

Phase 5 converts the deterministic intelligence generated in Phases 2–4 into a robust machine-learning classification pipeline.

The system must:

- prepare a trustworthy training dataset
- prevent data leakage
- generate a stable feature matrix
- train multiple ML models
- compare individual models
- train and evaluate an ensemble
- handle class imbalance correctly
- perform cross-validation and hyperparameter tuning
- calibrate model probabilities
- select an operating threshold using validation data
- generate complete evaluation metrics
- store reproducible model artifacts
- provide feature importance and explainability
- expose a safe inference interface for later phases

The goal is **not** to claim a high accuracy number. The goal is to build a reproducible, leakage-resistant, measurable, explainable and production-ready phishing ML pipeline.

---

# 2. Critical Rules

## 2.1 Do Not Rewrite Blindly

Before changing code, inspect the complete existing SecureSight repository.

Identify:

- current dataset
- current labels
- current feature extraction
- current models
- preprocessing
- training scripts
- evaluation scripts
- saved model artifacts
- prediction/inference code
- API endpoints
- existing tests

Create:

```text
docs/ML_AUDIT.md
```

Document what already exists before modifying it.

## 2.2 Never Fake Metrics

Do not hard-code or claim:

```text
Accuracy >95%
```

unless the final untouched test set actually produces that result.

Report the actual measured values.

## 2.3 Never Leak Test Data

The final test set must not influence:

- feature selection
- preprocessing
- hyperparameter tuning
- model selection
- calibration
- threshold selection

The test set is for final evaluation only.

## 2.4 Do Not Mix Phase 6 Into Phase 5

Phase 5 produces reliable model predictions/probabilities.

The final SecureSight risk-score engine belongs to Phase 6.

---

# 3. ML Architecture

```text
Raw Dataset
    |
    v
Dataset Validation
    |
    v
Cleaning + Deduplication
    |
    v
Leakage Prevention
    |
    v
Phase 2–4 Feature Generation
    |
    v
Train / Validation / Test Split
    |
    v
Preprocessing Pipeline
    |
    +-------------------+
    |                   |
    v                   v
Logistic Regression  Random Forest
    |                   |
    +---------+---------+
              |
              v
           XGBoost
              |
              v
       Model Comparison
              |
              v
       OOF Predictions
              |
              v
       Ensemble / Stacking
              |
              v
       Probability Calibration
              |
              v
       Threshold Selection
              |
              v
       Untouched Test Set
              |
              v
       Final Evaluation
              |
              v
       Versioned Artifact
              |
              v
          Inference API
```

---

# 4. Dataset Architecture

Adapt this structure to the existing project rather than creating duplicate directories:

```text
data/
├── raw/
├── processed/
├── external/
├── fixtures/
└── metadata/
```

Recommended metadata:

```text
data/metadata/
├── dataset_manifest.json
├── dataset_hash.json
└── label_definition.json
```

---

# 5. Dataset Provenance

Every dataset used for training must have documented provenance.

Record:

```text
dataset_name
dataset_source
source_url
collection_date
license
dataset_version
number_of_samples
number_of_features
label_distribution
preprocessing_steps
dataset_hash
```

If multiple datasets are combined, document:

- each source
- each dataset size
- label mapping
- duplicate handling
- conflicting-label handling
- final dataset composition

Do not silently mix datasets.

---

# 6. Label Definition

Use an explicit binary target unless the existing project intentionally uses another target.

Recommended:

```text
0 = legitimate
1 = phishing
```

Create:

```text
docs/LABEL_DEFINITION.md
```

Example:

```json
{
  "0": "legitimate",
  "1": "phishing"
}
```

If the existing dataset contains labels such as:

```text
safe
malicious
benign
phishing
unknown
```

create an explicit mapping and document it.

Do not silently change label semantics.

---

# 7. Data Cleaning

Validate:

- duplicate URLs
- duplicate normalized URLs
- duplicate domains
- malformed records
- missing labels
- invalid labels
- NaN values
- infinite values
- corrupted rows
- inconsistent encodings
- missing feature values

Generate a cleaning summary:

```text
Original samples
Removed exact duplicates
Removed normalized duplicates
Removed invalid records
Removed invalid labels
Final samples
```

Do not remove large numbers of records without documenting why.

---

# 8. Duplicate and Domain Leakage Detection

This is critical for phishing datasets.

Detect at minimum:

```text
exact URL duplicates
normalized URL duplicates
registrable-domain duplicates
```

Example:

```text
https://example.com/login
https://example.com/account
https://example.com/verify
```

should not automatically be treated as independent evidence.

When appropriate, use domain-level grouping so related URLs do not appear across training and test data.

---

# 9. Train / Validation / Test Strategy

Preferred starting point:

```text
Training:   70%
Validation: 15%
Testing:    15%
```

The exact ratio should be chosen based on the actual dataset size.

Use stratification when appropriate.

For datasets containing multiple URLs per domain, prefer group-aware splitting by registrable domain.

Possible strategies:

```text
StratifiedKFold
StratifiedGroupKFold
GroupShuffleSplit
```

depending on the dataset.

If timestamps exist, also consider temporal validation:

```text
Older records -> training
Later records -> validation
Newest records -> testing
```

Document which strategy was actually used and why.

---

# 10. Feature Matrix

The ML system must consume the canonical features produced by Phases 2–4.

Potential feature groups include:

## URL Features

```text
url_length
hostname_length
path_length
query_length
fragment_length
digit_count
special_character_count
hyphen_count
dot_count
slash_count
encoded_character_ratio
entropy
subdomain_count
ip_host
punycode_detected
shortener_detected
suspicious_token_count
```

## Domain Features

```text
domain_age_days
registrar_present
dns_a_present
dns_aaaa_present
dns_mx_present
dns_ns_present
ip_reputation
domain_reputation
asn_information
tls_valid
tls_expiry_days
```

## HTML Features

```text
html_size
script_count
iframe_count
form_count
input_count
password_input_count
hidden_element_count
external_resource_count
```

## Content Features

```text
urgency_score
credential_request_score
financial_language_score
login_language_score
security_language_score
phishing_keyword_count
brand_domain_mismatch
```

## Behavioral Features

Where implemented:

```text
redirect_count
cross_domain_redirect
final_domain_changed
resource_domain_count
```

**Do not invent features that do not exist in the implemented Phase 2–4 pipeline.**

The final feature list must be generated from the actual repository implementation.

---

# 11. Feature Schema Versioning

Every model must declare the feature schema against which it was trained.

Example:

```json
{
  "feature_schema_version": "4.0",
  "model_version": "5.0.0"
}
```

If inference receives an incompatible feature schema:

- reject it
- migrate it explicitly
- or return a clear schema mismatch error

Never silently reorder or rename features.

---

# 12. Deterministic Feature Ordering

Create one canonical feature registry.

Example:

```python
FEATURE_ORDER = [
    "url_length",
    "hostname_length",
    "path_length",
    "digit_count",
    "entropy",
    "subdomain_count"
]
```

The same order must be used during:

- training
- validation
- testing
- inference
- explainability

Feature ordering must be deterministic.

---

# 13. Missing Value Handling

External intelligence may be unavailable.

Examples:

```text
DNS unavailable
WHOIS unavailable
TLS unavailable
reputation provider unavailable
```

Missing information must not automatically become:

```text
phishing
```

Use an explicit preprocessing strategy such as:

- median imputation
- constant sentinel
- missingness indicators

Choose based on the actual feature types and document the decision.

---

# 14. Feature Scaling

Use model-appropriate preprocessing.

### Logistic Regression

Usually benefits from standardized numeric features.

### Random Forest

Does not require standardization.

### XGBoost

Generally does not require standardization.

Do not fit scaling/imputation on the complete dataset before splitting.

Correct pattern:

```text
Training fold
    |
fit preprocessing
    |
transform validation fold
```

Use sklearn pipelines where appropriate.

---

# 15. Class Imbalance

Inspect the class distribution before training.

Record:

```text
legitimate_count
phishing_count
class_ratio
```

If imbalance is significant, evaluate:

- class weights
- sample weights
- carefully applied resampling

If oversampling is used, it must happen only inside the training folds.

Never resample the test set.

---

# 16. Baseline

Establish a baseline before complex models.

At minimum:

```text
DummyClassifier
```

and:

```text
Logistic Regression
```

This establishes whether the advanced system provides meaningful improvement.

---

# 17. Model 1 — Logistic Regression

Implement Logistic Regression as the interpretable baseline.

Evaluate parameters such as:

```text
C
penalty
solver
class_weight
max_iter
```

Use a proper preprocessing pipeline.

Record:

```text
model
preprocessor
feature names
hyperparameters
metrics
```

---

# 18. Model 2 — Random Forest

Implement Random Forest.

Potential parameters:

```text
n_estimators
max_depth
min_samples_split
min_samples_leaf
max_features
class_weight
```

Tune based on validation/CV performance.

Record feature importance.

Do not use unnecessarily large forests without measuring their benefit and inference cost.

---

# 19. Model 3 — XGBoost

If XGBoost is compatible with the current environment, implement it.

Potential parameters:

```text
n_estimators
max_depth
learning_rate
subsample
colsample_bytree
min_child_weight
reg_alpha
reg_lambda
```

Do not hard-code values without evaluation.

If XGBoost cannot be supported in the deployment environment, provide a documented fallback rather than breaking SecureSight.

---

# 20. Cross-Validation

Use cross-validation for model selection.

Preferred:

```text
StratifiedKFold
```

or, when domain grouping is necessary:

```text
StratifiedGroupKFold
```

Every fold must independently fit preprocessing.

Correct:

```text
Fold
 |
 +-- training subset
 |      |
 |      +-- fit preprocessing
 |      +-- fit model
 |
 +-- validation subset
        |
        +-- transform using training preprocessing
        +-- evaluate
```

Never fit preprocessing on the complete dataset before cross-validation.

---

# 21. Hyperparameter Tuning

Use:

```text
RandomizedSearchCV
```

or:

```text
GridSearchCV
```

For larger search spaces, Optuna may be considered if compatible with the existing project.

Do not tune against the final test set.

All tuning must use training/CV/validation data.

---

# 22. Required Evaluation Metrics

Every model must report:

```text
Accuracy
Precision
Recall
F1 Score
ROC-AUC
PR-AUC
False Positive Rate
False Negative Rate
Confusion Matrix
```

For phishing detection, pay particular attention to:

```text
Recall
Precision
FPR
FNR
PR-AUC
```

Accuracy alone is insufficient.

---

# 23. Confusion Matrix

Generate:

```text
                 Predicted
              Legit   Phishing
Actual Legit    TN       FP
Actual Phish    FN       TP
```

Interpretation:

- **TP:** phishing correctly detected
- **TN:** legitimate correctly classified
- **FP:** legitimate incorrectly classified as phishing
- **FN:** phishing incorrectly classified as legitimate

Both FP and FN matter.

---

# 24. Metric Definitions

Use reliable sklearn implementations where possible.

### Precision

```text
TP / (TP + FP)
```

### Recall

```text
TP / (TP + FN)
```

### F1

```text
2 * Precision * Recall / (Precision + Recall)
```

### False Positive Rate

```text
FP / (FP + TN)
```

### False Negative Rate

```text
FN / (FN + TP)
```

---

# 25. ROC-AUC

Generate ROC-AUC from prediction probabilities/scores rather than hard labels.

Generate:

```text
ROC curve
```

for each relevant model.

---

# 26. Precision-Recall Curve

Because phishing datasets can be imbalanced, generate:

```text
Precision-Recall curve
PR-AUC
```

This should be included in the model evaluation report.

---

# 27. Model Comparison

Generate a comparison table:

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Dummy Baseline | — | — | — | — | — | — | — | — |
| Logistic Regression | — | — | — | — | — | — | — | — |
| Random Forest | — | — | — | — | — | — | — | — |
| XGBoost | — | — | — | — | — | — | — | — |
| Ensemble | — | — | — | — | — | — | — | — |

Values must be actual measured values.

---

# 28. Ensemble Architecture

Evaluate whether combining the models improves performance.

Recommended stacking architecture:

```text
Feature Vector
      |
      +--------------------+
      |         |          |
      v         v          v
     LR         RF        XGBoost
      |         |          |
      +---------+----------+
                |
        Out-of-Fold Predictions
                |
                v
           Meta Learner
                |
                v
        Final Probability
```

---

# 29. Prevent Ensemble Leakage

Do not train base models on all training data and then use predictions on that same data to train the meta-model.

Use out-of-fold predictions.

Example:

```text
Fold 1:
Train base models on folds 2–5
Predict fold 1

Fold 2:
Train base models on folds 1,3,4,5
Predict fold 2

...
```

Combine all validation predictions into an OOF matrix.

Train the meta-learner only on those OOF predictions.

---

# 30. Meta-Learner

Start with:

```text
Logistic Regression
```

Meta-model inputs can include:

```text
LR_probability
RF_probability
XGB_probability
```

Output:

```text
ensemble_probability
```

Keep the meta-model simple unless a more complex model demonstrates a measurable benefit.

---

# 31. Alternative — Soft Voting

Also compare against weighted soft voting where useful.

Conceptually:

```text
P_final =
w1 * P_LR +
w2 * P_RF +
w3 * P_XGB
```

Weights must be derived from validation evidence rather than manually chosen to improve reported results.

Select stacking or voting empirically.

---

# 32. Probability Calibration

A classifier probability is not automatically a trustworthy confidence value.

Example:

```text
Prediction: phishing
Probability: 0.97
```

does not automatically mean:

> The model is correct 97% of the time.

Evaluate calibration.

Possible methods:

```text
Platt scaling
Isotonic regression
```

Use validation data correctly and avoid test-set leakage.

---

# 33. Confidence vs Risk

Keep these concepts separate.

### Model Probability

Example:

```text
phishing_probability = 0.91
```

This represents the model's estimated class probability.

### SecureSight Risk Score

This will later combine:

```text
ML probability
domain intelligence
reputation
behavior
detection evidence
```

The final risk engine belongs to Phase 6.

---

# 34. Threshold Selection

Do not automatically assume:

```text
threshold = 0.50
```

Evaluate thresholds across a suitable range, for example:

```text
0.10
0.15
0.20
...
0.90
```

For each threshold calculate:

```text
precision
recall
F1
FPR
FNR
```

Choose the final operating threshold using validation data and the intended SecureSight operating mode.

Example:

```text
Detection mode:
prioritize recall

Blocking mode:
control false positives more aggressively
```

Document the reason for the selected threshold.

---

# 35. Threshold Analysis Report

Generate:

| Threshold | Precision | Recall | F1 | FPR | FNR |
|---:|---:|---:|---:|---:|---:|
| 0.30 | — | — | — | — | — |
| 0.40 | — | — | — | — | — |
| 0.50 | — | — | — | — | — |
| 0.60 | — | — | — | — | — |
| 0.70 | — | — | — | — | — |

Use actual values.

---

# 36. Feature Importance

Provide model explanations.

For tree models, evaluate:

```text
feature importance
```

Also consider:

```text
Permutation Importance
```

Do not rely only on raw tree feature importance.

---

# 37. SHAP Explainability

If compatible with the environment, implement SHAP for appropriate models.

Example output:

```text
Prediction: PHISHING

Top contributing features:

+ suspicious_token_count
+ credential_request_score
+ brand_domain_mismatch
+ url_entropy
+ domain_age_days
```

The actual features and impact values must come from the model.

Never fabricate explanations.

---

# 38. Local Explanation

The ML layer should eventually support:

```json
{
  "prediction": "phishing",
  "probability": 0.94,
  "explanations": [
    {
      "feature": "brand_domain_mismatch",
      "value": 1,
      "impact": "positive"
    }
  ]
}
```

This will be integrated more fully in Phase 7.

---

# 39. Model Artifact

Store a complete versioned inference package.

Possible structure:

```text
models/
└── v5/
    ├── model.pkl
    ├── preprocessor.pkl
    ├── feature_schema.json
    ├── model_metadata.json
    ├── threshold.json
    └── metrics.json
```

Adapt to the repository's existing model format.

---

# 40. Model Metadata

Example:

```json
{
  "model_version": "5.0.0",
  "feature_schema_version": "4.0",
  "model_type": "stacking_ensemble",
  "training_date": "YYYY-MM-DDTHH:MM:SSZ",
  "dataset_version": "dataset-version",
  "dataset_hash": "hash",
  "random_seed": 42,
  "threshold": 0.50,
  "calibration": "isotonic",
  "metrics": {}
}
```

Record enough metadata to reproduce and audit the model.

---

# 41. Reproducibility

Record:

```text
Python version
library versions
dataset version
dataset hash
feature schema version
random seed
model hyperparameters
training configuration
calibration configuration
threshold
```

Set deterministic seeds where supported.

Create or update:

```text
requirements-ml.txt
```

only if this fits the project's existing dependency strategy.

---

# 42. Safe Model Loading

Model artifacts can be dangerous when deserialized using formats such as pickle/joblib.

Never load arbitrary user-provided model files.

Only load trusted internal artifacts.

If pickle/joblib is used:

```text
Never deserialize untrusted model files.
```

Model loading must come from a controlled model directory or trusted artifact source.

---

# 43. Inference Service

Implement a clean prediction flow:

```text
Feature Vector
      |
Schema Validation
      |
Preprocessor
      |
Ensemble
      |
Calibration
      |
Threshold
      |
Prediction
```

Example:

```json
{
  "prediction": "phishing",
  "probability": 0.93,
  "threshold": 0.50,
  "model_version": "5.0.0",
  "feature_schema_version": "4.0"
}
```

Do not convert this into the final SecureSight risk score yet.

---

# 44. API Endpoint

If FastAPI is used, expose an endpoint similar to:

```text
POST /api/v1/ml/predict
```

Input must be validated.

Training endpoints must not be public.

Training should be:

```text
offline
admin-controlled
CI/CD controlled
```

and must never be triggered by arbitrary public requests.

---

# 45. ML Error States

Implement explicit errors such as:

```text
MODEL_NOT_FOUND
MODEL_VERSION_MISMATCH
FEATURE_SCHEMA_MISMATCH
INVALID_FEATURE_VECTOR
MISSING_REQUIRED_FEATURE
PREPROCESSING_FAILED
PREDICTION_FAILED
MODEL_LOAD_FAILED
```

A model failure must never silently return:

```text
SAFE
```

---

# 46. Evaluation Artifacts

Generate:

```text
reports/ml/
├── model_comparison.json
├── model_comparison.csv
├── confusion_matrix.json
├── classification_report.json
├── roc_curve.json
├── precision_recall_curve.json
├── threshold_analysis.json
├── calibration_report.json
├── feature_importance.json
└── final_evaluation.json
```

Visualizations may also be generated where useful.

---

# 47. Final Test Set

After completing:

- feature selection
- preprocessing decisions
- hyperparameter tuning
- model selection
- ensemble selection
- calibration strategy
- threshold selection

freeze the configuration.

Then evaluate the final model on the untouched test set.

Clearly report:

```text
Validation performance
Final test performance
```

Do not continue tuning after viewing final test results.

If the model is changed after test evaluation, the test evaluation is no longer a clean final evaluation and must be repeated with a fresh untouched test set.

---

# 48. Statistical Stability

When the dataset is sufficiently large, report cross-validation:

```text
mean score
standard deviation
```

Example:

```text
F1 = 0.941 ± 0.012
```

This is more informative than reporting a single score alone.

---

# 49. Model Selection Criteria

Do not select the model using accuracy alone.

A reasonable starting priority is:

```text
1. Security-relevant recall
2. False-positive rate
3. F1
4. PR-AUC
5. ROC-AUC
6. Accuracy
7. Inference cost
```

Adjust this based on the actual SecureSight deployment mode and document the final decision.

---

# 50. Performance Benchmarking

Measure:

```text
single prediction latency
batch prediction latency
model loading time
memory usage
```

Only report measured values.

Example format:

```text
Model loading: XXX ms
Single inference: XX ms
Batch inference: XXX ms / 100 samples
```

---

# 51. ML Logging

Log useful metadata such as:

```text
model_version
feature_schema_version
prediction
probability
latency
error
```

Avoid logging full raw URLs when they may contain:

```text
tokens
session IDs
credentials
personal information
```

Follow the privacy requirements established in earlier phases.

---

# 52. ML Tests

Create tests for:

## Dataset

```text
test_dataset_labels
test_duplicate_detection
test_missing_values
test_class_distribution
```

## Features

```text
test_feature_order
test_feature_schema
test_missing_feature_handling
```

## Models

```text
test_model_load
test_model_prediction
test_probability_range
test_prediction_shape
```

## Ensemble

```text
test_oof_predictions
test_meta_model
test_ensemble_prediction
```

## Calibration

```text
test_probability_range
test_calibration_pipeline
```

## API

```text
test_predict_endpoint
test_invalid_feature_vector
test_schema_mismatch
test_model_missing
```

---

# 53. Regression Fixtures

Create deterministic fixtures:

```text
tests/fixtures/ml/
├── known_legitimate.json
├── known_phishing.json
└── edge_cases.json
```

These are regression tests, not a replacement for the real test set.

Do not require every fixture to have identical predictions across every future model version unless that behavior is intentionally frozen.

---

# 54. Model Versioning

Use explicit model versions.

Example:

```text
5.0.0
```

Suggested meaning:

```text
MAJOR = incompatible model/schema change
MINOR = improved compatible model
PATCH = artifact/configuration fix
```

Every prediction must be traceable to a model version.

---

# 55. Documentation Required

Create:

```text
docs/ML_ARCHITECTURE.md
docs/DATASET.md
docs/ML_FEATURES.md
docs/MODEL_TRAINING.md
docs/MODEL_EVALUATION.md
docs/ENSEMBLE.md
docs/MODEL_EXPLAINABILITY.md
docs/MODEL_VERSIONING.md
docs/ML_SECURITY.md
docs/PHASE_05_REPORT.md
```

---

# 56. PHASE_05_REPORT.md

The report must contain:

## Objective

What Phase 5 implemented.

## Existing ML Audit

What existed before this phase.

## Dataset

Source, size, labels, cleaning, provenance.

## Leakage Prevention

How URL/domain duplicates and leakage were handled.

## Feature Pipeline

Which actual Phase 2–4 features were used.

## Models

- Logistic Regression
- Random Forest
- XGBoost
- Ensemble

## Training

Cross-validation and hyperparameter tuning.

## Evaluation

All relevant metrics.

## Confusion Matrix

Interpretation of:

```text
TP
TN
FP
FN
```

## Ensemble

How OOF stacking or voting was implemented.

## Calibration

How probabilities were calibrated.

## Threshold

Why the selected threshold was chosen.

## Explainability

Feature importance, permutation importance and/or SHAP.

## Security

Model loading and data-security controls.

## Performance

Latency and resource usage.

## Limitations

Document actual limitations, such as:

- dataset limitations
- missing reputation data
- domain grouping limitations
- unavailable temporal validation
- class imbalance
- model uncertainty

## Final Results

Use actual measured values only.

---

# 57. Recommended Directory Structure

Adapt this to the existing repository:

```text
SecureSight/
│
├── app/
│   ├── api/
│   ├── core/
│   ├── services/
│   ├── schemas/
│   └── ml/
│
├── ml/
│   ├── data/
│   ├── features/
│   ├── preprocessing/
│   ├── training/
│   ├── evaluation/
│   ├── ensemble/
│   ├── calibration/
│   └── inference/
│
├── models/
│   └── v5/
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── metadata/
│
├── reports/
│   └── ml/
│
├── tests/
│   └── ml/
│
└── docs/
```

Do not duplicate existing project directories if equivalent structures already exist.

---

# 58. Complete ML Pipeline

The final implementation should conceptually follow:

```text
Dataset
   ↓
Validation
   ↓
Cleaning
   ↓
Deduplication
   ↓
Leakage Prevention
   ↓
Feature Generation
   ↓
Group/Stratified Split
   ↓
Preprocessing
   ↓
Cross Validation
   ↓
+-------------------------+
| Logistic Regression     |
| Random Forest           |
| XGBoost                 |
+------------+------------+
             ↓
       Model Comparison
             ↓
      OOF Meta Training
             ↓
       Ensemble Selection
             ↓
          Calibration
             ↓
      Threshold Selection
             ↓
      Untouched Test Set
             ↓
       Final Evaluation
             ↓
      Versioned Artifact
             ↓
          Inference
```

---

# 59. What Phase 5 Must NOT Implement

Do not turn Phase 5 into unrelated development.

Do not implement here:

```text
Browser extension
Email scanner
Final risk scoring engine
Offensive exploitation
XSS scanner
SQL injection scanner
```

Phase 5 is specifically:

```text
DATA
+
FEATURES
+
ML MODELS
+
ENSEMBLE
+
EVALUATION
+
CALIBRATION
+
MODEL VERSIONING
```

---

# 60. Definition of Done

## Dataset

- [ ] Dataset provenance documented
- [ ] Labels documented
- [ ] Duplicates handled
- [ ] Leakage controls implemented
- [ ] Train/validation/test strategy documented

## Features

- [ ] Phase 2–4 feature schemas integrated
- [ ] Stable feature ordering implemented
- [ ] Missing values handled
- [ ] Feature versioning implemented

## Models

- [ ] Logistic Regression implemented
- [ ] Random Forest implemented
- [ ] XGBoost implemented where supported
- [ ] Baseline established
- [ ] Cross-validation implemented
- [ ] Hyperparameter tuning implemented

## Ensemble

- [ ] OOF predictions implemented
- [ ] Stacking/voting evaluated
- [ ] Leakage prevented
- [ ] Final ensemble selected empirically

## Evaluation

- [ ] Accuracy
- [ ] Precision
- [ ] Recall
- [ ] F1
- [ ] ROC-AUC
- [ ] PR-AUC
- [ ] FPR
- [ ] FNR
- [ ] Confusion matrix
- [ ] Threshold analysis
- [ ] Calibration analysis

## Explainability

- [ ] Feature importance
- [ ] Permutation importance where appropriate
- [ ] SHAP where compatible
- [ ] Local explanation foundation

## Production

- [ ] Model artifact versioned
- [ ] Metadata stored
- [ ] Feature schema stored
- [ ] Threshold stored
- [ ] Safe model loading
- [ ] Inference API implemented
- [ ] Explicit error states implemented

## Testing

- [ ] Dataset tests
- [ ] Feature tests
- [ ] Model tests
- [ ] Ensemble tests
- [ ] API tests
- [ ] Regression fixtures

## Documentation

- [ ] ML architecture
- [ ] Dataset documentation
- [ ] Training documentation
- [ ] Evaluation documentation
- [ ] Ensemble documentation
- [ ] Explainability documentation
- [ ] ML security documentation
- [ ] Phase 5 report

---

# 61. Codex / Trae Implementation Instructions

Follow these instructions strictly.

### Rule 1 — Inspect First

Read the entire existing repository and current ML pipeline before making changes.

### Rule 2 — Preserve Working Functionality

Do not unnecessarily rewrite existing SecureSight components.

### Rule 3 — Reuse Existing Feature Extractors

If Phase 2–4 implementations already exist, integrate them instead of creating duplicate feature-extraction logic.

### Rule 4 — Never Fake Metrics

Never modify evaluation code to make performance appear better.

### Rule 5 — Never Leak Test Data

The final test set must remain untouched until final evaluation.

### Rule 6 — Never Hard-Code Accuracy Claims

Only report actual measured results.

### Rule 7 — Keep Training and Inference Consistent

The preprocessing and feature ordering used during inference must match the trained model.

### Rule 8 — Version Everything

Model, feature schema, dataset, threshold and calibration configuration must be traceable.

### Rule 9 — Handle Failures Explicitly

A model failure must never silently produce a SAFE result.

### Rule 10 — Test Everything

After implementation, run:

```text
unit tests
ML tests
integration tests
API tests
```

Report all failures instead of hiding them.

### Rule 11 — Do Not Implement Phase 6 Early

Do not merge the final risk-score engine into Phase 5.

### Rule 12 — No Unsupported Claims

Do not claim:

- 95%+ accuracy
- production readiness
- zero false positives
- zero false negatives
- real-time performance

unless actual implementation and measurements support the claim.

### Rule 13 — Report Changes

At completion provide:

```text
Files created
Files modified
Files removed
Dependencies added
Models trained
Dataset used
Metrics obtained
Tests executed
Tests passed
Tests failed
Known limitations
Recommended next phase
```

---

# 62. Final Expected Result

At the end of Phase 5, SecureSight should have:

```text
URL Intelligence
       +
Domain Intelligence
       +
HTML/DOM Intelligence
       +
Content Intelligence
       ↓
Unified Feature Vector
       ↓
Validated Dataset
       ↓
Multiple ML Models
       ↓
Ensemble
       ↓
Calibrated Probability
       ↓
Validated Threshold
       ↓
Versioned Prediction
```

This prediction becomes the primary ML input for:

# Phase 6 — Risk Scoring & Confidence Engine

---

# 63. Phase 5 Success Standard

The success criterion is **not**:

> "Use Random Forest + XGBoost and say the accuracy is 95%."

The success criterion is:

> **Build a reproducible, leakage-resistant, measurable, explainable and production-ready phishing ML pipeline whose results can be technically defended in an interview and audited from dataset to final prediction.**
