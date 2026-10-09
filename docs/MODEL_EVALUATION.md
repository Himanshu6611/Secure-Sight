# SecureSight — Model Evaluation

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Evaluation Metrics Contract

Per Phase 5 spec §22, every trained model (baseline, 3 bases, 2 ensembles, final calibrated) is evaluated against the following metrics, each defined explicitly. Metrics are computed via `ml/evaluation.py::compute_full_metrics(y_true, y_pred, y_proba)` and persisted as JSON + CSV rows in `reports/ml/`.

## 2. Full Metric Set

### 2.1 Primary Classification Metrics

Let N = total samples, P = actual positives (phishing = 1), N = actual negatives (legitimate = 0).

Confusion matrix terminology (consistent throughout codebase / docs / API):

|          | Predicted 0 (legitimate) | Predicted 1 (phishing) |
|---|---|---|
| Actual 0 | **TN** True Negative | **FP** False Positive |
| Actual 1 | **FN** False Negative | **TP** True Positive |

Derived metrics:

| Metric | Formula | Semantics | Recorded Name |
|---|---|---|---|
| Accuracy | (TP + TN) / (TP + TN + FP + FN) | Overall correctness | `accuracy` |
| Precision (P) | TP / (TP + FP) | When "phishing" is predicted, how often is it correct? | `precision` |
| Recall (R) / Sensitivity / TPR | TP / (TP + FN) | Fraction of true phishing URLs that are caught | `recall` |
| F1 | 2·P·R / (P + R) | Harmonic mean of precision & recall (primary tuning target) | `f1` |
| False Positive Rate (FPR) | FP / (FP + TN) | Legitimate URLs wrongly flagged — user annoyance metric | `false_positive_rate` |
| False Negative Rate (FNR) | FN / (FN + TP) | Phishing URLs missed — security risk metric | `false_negative_rate` |

All rates are reported in [0, 1]. There is no percentage-multiply-100 anywhere in code; consumers multiply when displaying.

### 2.2 Ranking / Threshold-Agnostic Metrics

| Metric | Sklearn function | Semantics | Recorded Name |
|---|---|---|---|
| ROC-AUC | `sklearn.metrics.roc_auc_score` | Area under Receiver-Operating Characteristic (TPR vs FPR) | `roc_auc` |
| PR-AUC | `sklearn.metrics.average_precision_score` | Area under Precision–Recall curve; more meaningful for imbalanced classes | `pr_auc` |

### 2.3 Threshold Analysis (81-point sweep)

`ml.evaluation.threshold_analysis(y_true, y_proba, min_t=0.10, max_t=0.90, step=0.01)` — computes for every threshold t:

```json
{
  "threshold": 0.50,
  "accuracy":   0.98,
  "precision":  0.98,
  "recall":     0.98,
  "f1":         0.98,
  "fpr":        0.02,
  "fnr":        0.02
}
```

Saved to `reports/ml/threshold_analysis.json` as a list of 81 entries, suitable for ROC-style dashboard plotting.

### 2.4 Operating-Point Selection

`ml.evaluation.select_optimal_threshold(threshold_results, priority="f1")`

Priority rules (§34 of the spec):

| priority | Objective | Constraint |
|---|---|---|
| `"f1"` (default) | Row with the highest F1 | None |
| `"recall"` | Row with the highest recall | Must have F1 ≥ 0.95 × best-F1 |
| `"precision"` | Row with the highest precision | Must have F1 ≥ 0.95 × best-F1 |

If the constraint cannot be met (e.g. no row has F1 ≥ 95% of best), it degrades gracefully to a row satisfying F1 ≥ 90% of best, otherwise returns the pure max-F1 row with a warning field in its dict.

Chosen operating-point is saved to:

```text
models/v5/threshold.json           —  consumed at inference time
reports/ml/optimal_threshold.json  —  audit trail
```

## 3. Confusion Matrix & Classification Report

### 3.1 Confusion Matrix (final test-set)

Saved to `reports/ml/confusion_matrix.json`:

```json
{
  "true_negative":  0,
  "false_positive": 0,
  "false_negative": 0,
  "true_positive":  0
}
```

Interpretation guidance (displayed in phase report, see `PHASE_05_REPORT.md`):

- **High FN (low recall)** → threshold is too high, or the model lacks discriminatory features for those samples. Action: lower threshold at cost of higher FPR, add more features for missed-domain classes.
- **High FP (low precision)** → threshold is too low. Action: raise threshold at cost of higher FNR, or tighten feature preprocessing (FPR is a user-facing concern — flagging legitimate banking login pages as phishing erodes trust).

### 3.2 sklearn Classification Report dict (test-set)

Saved to `reports/ml/classification_report.json` via `sklearn.metrics.classification_report(..., output_dict=True)` so per-class precision / recall / f1 / support for `legitimate` (0) and `phishing` (1) are preserved exactly as produced by the canonical library.

## 4. Probability Calibration

- A calibrated model is one where `P(y=1 | predicted_p = p) ≈ p` for all p.
- Phase 5 calibrates probabilities using isotonic regression on the validation split, never on the test split.
- `sklearn.calibration.calibration_curve` is used to produce per-bin `fraction_of_positives` vs `mean_predicted_value` for 10 uniform-width bins.
- **Expected Calibration Error (ECE)** is reported per the standard weighted average:
  `ECE = Σ (|bin| / N) · |avg_confidence − avg_accuracy|`.

Saved to `reports/ml/calibration_report.json`:

```json
{
  "validation_set": { "method": "isotonic", "report": { "expected_calibration_error": 0.012, ... } },
  "test_set_ece":     { "expected_calibration_error": 0.011, "fraction_of_positives": [...], "mean_predicted_value": [...] },
  "primary_model_type": "stacking_ensemble"
}
```

## 5. ROC & Precision-Recall Curves

Both are saved in `reports/ml/roc_curve.json` and `reports/ml/precision_recall_curve.json` as arrays:

- `roc_curve.json`: `{ "fpr": [...], "tpr": [...], "thresholds": [...] }`
- `precision_recall_curve.json`: `{ "precision": [...], "recall": [...], "thresholds": [...] }`

## 6. Model Comparison Table

`reports/ml/model_comparison.csv` + `.json` compare every candidate across validation metrics.

Rows (7 expected):

| Row Key | Description |
|---|---|
| `baseline` | `DummyClassifier(strategy="most_frequent")` |
| `logistic_regression` | Tuned Scikit-learn LogisticRegression with StandardScaler pipeline |
| `random_forest` | Tuned Scikit-learn RandomForestClassifier |
| `xgboost` (or `ExtraTreesFallback`) | Tuned XGBoost classifier (or ExtraTrees when xgboost package is not installed) |
| `soft_voting` | Soft voting over 3 bases with F1-weighted weights |
| `stacking_ensemble` | OOF 5-fold stacking with LogisticRegression meta-learner |

Columns (CSV header): `model, accuracy, precision, recall, f1, roc_auc, pr_auc, false_positive_rate, false_negative_rate, tn, fp, fn, tp, training_time_sec, cv_auc_mean, cv_auc_std`

## 7. Holdout Test-Set Evaluation Rules

The final untouched holdout (15% samples, domain-disjoint) is touched EXACTLY ONCE in the entire pipeline: at `training.py::run_final_test_evaluation`. All decisions before that step — feature selection, preprocessing stats, hyperparameter tuning, ensemble selection, calibration fit, threshold choice — use only train or validation. Violation would constitute test-data leakage and is a hard failure of §2.3 of the spec.

After evaluation, `models/v5/metrics.json` contains a snapshot of final test-set metrics for quick lookup by downstream consumers (Phase 6 risk engine / API / dashboards) without needing to parse the full reports directory.

## 8. Statistical Stability (CV Mean ± Std)

Per §48, per-model 5-fold CV ROC-AUC mean & standard deviation on a deterministic 20k-row stratified subsample of training data are stored in:

- `comparison[*].cv_stats.cv_auc_mean`
- `comparison[*].cv_stats.cv_auc_std`

Models whose CV std > 0.01 should be treated as unstable and possibly retuned with more regularization or smaller search spaces.

## 9. Performance Benchmarks

`models/v5/model_metadata.json.test_metrics` and `models/v5/metrics.json` record:

| Field | Meaning |
|---|---|
| `single_inference_ms_mean` | Mean ms over 10 single-sample `.predict_proba` calls |
| `single_inference_ms_std` | Standard deviation ms of same 10 calls |
| `batch_inference_ms_total` | Wall-clock ms for 1 × `predict_proba(X_test)` 31,354 rows |
| `batch_inference_ms_per_100` | Above, normalised to 100 rows |

These are used in `docs/PHASE_05_REPORT.md` §Performance.
