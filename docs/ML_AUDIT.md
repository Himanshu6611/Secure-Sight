# SecureSight — ML System Audit Report

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Executive Summary
This document provides a thorough technical audit of SecureSight's existing machine learning artifacts, datasets, feature extraction code, training pipelines, and inference interfaces prior to Phase 5 implementation.

---

## 2. Existing ML Pipeline Audit

### 2.1 Persisted Model Artifacts
- **File Location:** `models/ensemble.pkl` (34.4 MB)
- **Model Architecture:** `sklearn.ensemble.VotingClassifier` (Soft Voting)
- **Base Estimators:**
  1. `LogisticRegression` (with `StandardScaler` pipeline, `C=5.0`, `class_weight='balanced'`) — Weight: `0.2`
  2. `RandomForestClassifier` (`n_estimators=300`, `max_depth=20`, `min_samples_split=5`, `class_weight='balanced'`) — Weight: `0.6`
  3. `DecisionTreeClassifier` (`max_depth=12`, `min_samples_leaf=5`, `class_weight='balanced'`) — Weight: `0.2`
- **Metadata File:** `models/metadata.json`

### 2.2 Datasets & Provenance
- **Raw Sources:**
  - `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (235,795 rows)
  - `data/raw/Training Dataset.arff` (UCI ARFF - skipped due to missing raw URL string column)
- **Cleaned Dataset:** `data/cleaned.csv` (232,472 deduplicated rows)
- **Feature Store:** `data/features.parquet` (11 numerical features + binary `label`)
- **Label Distribution:** Binary `0` (legitimate, ~50.2%), `1` (phishing, ~49.8%).

### 2.3 Feature Generation (Legacy)
The legacy model relies exclusively on 11 basic URL string statistics defined in `utils/feature_extraction.py`:
1. `url_len`
2. `dot_cnt`
3. `hyphen_cnt`
4. `special_cnt`
5. `digit_cnt`
6. `token_hits`
7. `domain_len`
8. `subdomain_depth`
9. `has_ip`
10. `https`
11. `entropy`

**Key Observation:** The legacy ML model does **NOT** currently consume the rich features produced by Phase 2 (URL intelligence), Phase 3 (Domain, DNS, TLS, WHOIS, reputation intelligence), or Phase 4 (HTML, DOM, forms, script obfuscation, content NLP intelligence).

---

## 3. Data Leakage & Validation Audit

1. **Splitting Method:** Legacy script `scripts/train_ensemble.py` uses `train_test_split` with 80% train / 20% test stratified by label.
2. **Domain Group Leakage Risk:** URLs originating from the same registrable domain (e.g., `example.com/login` and `example.com/verify`) could be present in both train and test splits, artificially inflating evaluation accuracy.
3. **Resampling:** SMOTE (`imblearn.over_sampling.SMOTE`) was applied to the training set.

---

## 4. Inference & API Audit

- **Inference Service:** `utils/model.py` (`load_ensemble()`, `predict_proba()`)
- **Integration Point:** `app/services/scans.py` (`scan_url()`)
- **Decision Threshold:** Legacy system applies hardcoded `probability >= 0.85` or `risk >= 70`. Thresholding was not calibrated or empirically selected via ROC/PR curves.

---

## 5. Audit Findings & Upgrade Strategy for Phase 5

| Area | Current Legacy State | Phase 5 Target Upgrade |
| :--- | :--- | :--- |
| **Feature Set** | 11 basic URL character features | Unified feature matrix combining Phase 2, 3 & 4 features (URL, Domain, DNS, TLS, HTML, DOM, NLP) |
| **Splitting Strategy** | Random Stratified Split | Registrable Domain Group-Based Stratified Split (`StratifiedGroupKFold` / Domain-grouped holdout) |
| **Ensemble Model** | Soft Voting (`VotingClassifier`) | Out-of-Fold (OOF) Stacking Ensemble with Logistic Regression Meta-Learner + XGBoost support |
| **Probability Calibration** | Raw uncalibrated probabilities | Isotonic Regression / Platt Scaling calibration |
| **Thresholding** | Fixed 0.85 arbitrary cutoff | Empirical Precision-Recall / FPR tradeoff optimization |
| **Explainability** | Generic UI dictionary | Feature Importance & SHAP / Permutation Importance integration |
| **Artifact Schema** | Versionless metadata | Versioned model package (`v5`, `feature_schema_version="4.0"`, `model_version="5.0.0"`) |
