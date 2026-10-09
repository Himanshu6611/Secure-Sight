# SecureSight — Ensemble

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Ensemble Strategy Rationale

Single classifiers each have complementary strengths:

- **Logistic Regression**: fast, interpretable, low variance; good baseline for linear signal (entropy, URL length, token counts).
- **Random Forest / ExtraTrees**: handles non-linear interactions, robust to monotonic feature scaling, gives native `feature_importances_`.
- **XGBoost (or ExtraTrees fallback)**: gradient-boosted trees model additive structure that bagging forests sometimes miss.

An ensemble combines these strengths. Two candidates are built from the same 3 fitted base estimators and compared empirically on the **validation F1** score. F1 wins ties.

## 2. Candidate A — Soft Voting Ensemble

Implemented in `ml/training.py::train_soft_voting`.

Uses `sklearn.ensemble.VotingClassifier` with `voting="soft"`. Weights are proportional to validation F1 and initialised to `[0.2, 0.6, 0.2]` — default weight favours the tree-based middle model (historically the strongest single model on URL datasets) but the empirical final selection compares stack vs voting anyway so the initial weights don't bias results.

Soft-voting semantics (not hard-voting) were chosen specifically because:

1. The downstream Phase 6 engine requires **calibrated probabilities**, not just classes.
2. Averaging probabilities is mathematically smoother than mode aggregation, and produces a strictly more informative ranking curve.

## 3. Candidate B — OOF Stacking Ensemble

Implemented in `ml/ensemble.py::StackingEnsembleClassifier`.

This is a 2-level stacking classifier with **Out-of-Fold** meta-training to avoid meta-overfitting.

### 3.1 Stacking Architecture

```
                ┌───────────────────────────┐
                │  Level 0: Base Learners   │
X_train ─────► │  LR  ───►  proba_LR[:,1]  │
          │    │  RF  ───►  proba_RF[:,1]  │
          │    │  XGB ───►  proba_XGB[:,1] │
          │    └───────────────────────────┘
          │                │ (3 stacked probabilities)
          │                ▼
          │     Out-of-Fold 5-fold Stratified split
          │           ┌───────────────────┐
          │           │ Meta-Learner:    │
          └────────►  │ LogisticRegression│  ──► meta-proba
                      └───────────────────┘
```

### 3.2 Leakage-Free Meta-Training

Critical: the meta-learner never sees the same training instance in its base-level training fold AND its meta-training fold. Specifically:

1. Initialise empty matrix `X_meta` of shape (N_train, 3).
2. For each of `k=5` `StratifiedKFold(shuffle=True, random_state=42)` splits `(train_idx, val_idx)`:
   a. `clone` each of the 3 base estimators.
   b. Refit clone on `X_train[train_idx], y_train[train_idx]`.
   c. Predict probabilities for `X_train[val_idx]`.
   d. Store predictions into `X_meta[val_idx, :]`.
3. Fit the meta-learner on `(X_meta, y_train)`.
4. After meta-training completes, refit the **original** (not cloned) base estimators on the FULL training set so production inference uses the strongest possible base models.

Step 4 + the OOF training means the meta-learner's training signal is unbiased with respect to the base-learners' final production refit. This is the "stacking with holdout" recipe that won most Kaggle tabular competitions, and is faithful to Phase 5 spec §27.

### 3.3 Meta-Learner Choice

`LogisticRegression(C=1.0, class_weight="balanced", random_state=42)`.

Rationale:

- A simple linear meta-learner avoids overfitting to a 3-dimensional meta-space (3 base learners).
- Its learned coefficients are interpretable: inspect `coef_[0]` to see how much weight stacking assigns to each base learner's probability signal.
- It never saturates or clips probabilities, which keeps the downstream isotonic calibration step well-conditioned.

## 4. Empirical Selection

After fitting both ensemble candidates on the same 3 pre-fitted bases:

```python
if voting_val_f1 > stacking_val_f1:
    primary_uncalibrated = voting_model
    primary_type = "soft_voting"
else:
    primary_uncalibrated = stacking_ensemble
    primary_type = "stacking_ensemble"
```

The losing candidate's metrics are still written to `reports/ml/model_comparison.{json,csv}` for reproducibility and audit. There is no silent winner.

## 5. Ensemble as Production Model

The winning ensemble is wrapped by `CalibratedClassifierCV(cv="prefit")` via `ml/calibration.py::calibrate_classifier`. The wrapper is fitted ONLY on `(X_val, y_val)`, never on the test split. This produces the final `calibrated_model` that is persisted to `models/v5/model.pkl` and used in production inference.

## 6. Loading & Wrapper Compatibility

Loading the calibrated ensemble with `joblib.load` yields a sklearn classifier with `.predict_proba(X)` method. Consumers (Flask API endpoint, `SecureSightPredictor`, Phase 6) rely on that method exclusively; never on `.predict()`, because threshold policy is applied explicitly at inference time using `models/v5/threshold.json`.

The calibrated wrapper does retain the ability to recurse into its inner ensemble when the explainability module walks the attribute tree for `feature_importances_` — see `ml/explainability.py::_extract_tree_importance` for the recursive walk.

## 7. Failure Modes & Degradation

| Failure | Handling |
|---|---|
| A base estimator's `predict_proba` raises | The whole ensemble predict_proba raises; upstream code maps this to `PREDICTION_FAILED`. This is INTENTIONAL — never silently drop a base learner and degrade to 2-of-3 voting without an explicit retrain. |
| Meta-learner produces NaN probability | Inference pipeline clamps and then rejects (`PREDICTION_FAILED` + detail text). Endpoint never returns SAFE. |
| Both candidates F1 < baseline dummy | Orchestrator logs a warning but still picks the better one. The phase report flags it as a Limitation / failure. |
