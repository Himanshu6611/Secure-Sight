# SecureSight — Model Explainability

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## 1. Explainability Deliverables (per §37 & §38)

Phase 5 produces two classes of explainability artefact:

1. **Global** — what features matter on average across the validation set.
2. **Local** — which features pushed a single URL's prediction toward "phishing" or "legitimate".

All artefacts are produced at training time from the validation set (not test, to avoid leakage) and persisted to:

```text
reports/ml/feature_importance.json   — global ranking
reports/ml/local_explanations.json   — 10 sampled local explanations
```

## 2. Global Feature Importance

### 2.1 Two Engines, Smart Fallback

`ml/explainability.py::global_feature_importance(model, X_val, y_val, feature_names)`

Strategy priority:

| Priority | Engine | When used |
|---|---|---|
| 1 | **Tree-native `feature_importances_`** | If the calibrated wrapper or any of its nested ensemble/pipeline steps exposes `feature_importances_` via attribute walk. Cheapest. |
| 2 | **`sklearn.inspection.permutation_importance`** | Otherwise, or whenever `engine="permutation"` is passed explicitly. |

### 2.2 Attribute Walk for Wrapped Models

Trees don't always live at top-level after ensemble + calibration wrapping. `_extract_tree_importance(obj)` walks:

- `sklearn.pipeline.Pipeline.named_steps[*]`
- `sklearn.calibration.CalibratedClassifierCV.estimator` / `.calibrated_classifiers_[0].estimator`
- `sklearn.ensemble.VotingClassifier.estimators_` (or `named_estimators_` dict)
- Custom `ml.ensemble.StackingEnsembleClassifier.fitted_base_estimators_` list (averaged across fitted bases, weighted by meta-learner coefs when available)

The per-base weights are normalised to sum to 1, so a stacking meta-learner coefficient of e.g. 0.5 for RF → RF's feature importance vector contributes 0.5-weighted.

### 2.3 Permutation Importance (model-agnostic, fallback)

`sklearn.inspection.permutation_importance(..., scoring="roc_auc", n_repeats=3, n_jobs=1)` on a deterministic stratified 8000-row subsample of validation (full 33k rows would be >45 min). For each feature `f`, shuffle its column 3 times independently; the permutation importance is the mean ROC-AUC drop relative to baseline.

Output is a dict `{feature_name: mean_importance_value}` sorted in descending order — the format required by the downstream visualisation tooling in Phase 6 risk dashboard.

## 3. Local (Per-Sample) Explanations

### 3.1 Required Output Shape (§38 Contract)

`explain_sample(model, X_sample, feature_names, y_true=None, y_proba=None, top_k=5)` returns:

```json
{
  "prediction":      "phishing | legitimate",
  "probability":     0.872,
  "engine":          "shap_tree | shap_linear | shap_kernel | permutation_perturbation",
  "explanations": [
    {"feature": "entropy",     "value": 5.2, "impact": "positive"},
    {"feature": "url_length",  "value": 220, "impact": "positive"},
    {"feature": "is_ip_host",  "value": 1,   "impact": "positive"},
    {"feature": "tls_valid",   "value": 0,   "impact": "positive"},
    {"feature": "subdomain_count", "value": 4, "impact": "negative"}
  ]
}
```

Where `impact ∈ {"positive", "negative"}` with semantics:

- `positive` when the feature pushes the prediction in the same direction as the final output (e.g. for a "phishing" prediction, a feature whose contribution increases p̂).
- `negative` when the feature pushes in the opposite direction (protective / risk-reducing).

### 3.2 Engine Priority & Graceful Fallback

| Priority | Engine | Prerequisite | Detail |
|---|---|---|---|
| 1 | `shap_tree` | `import shap` succeeds, model has an inner tree-based estimator | `shap.TreeExplainer` on first tree estimator. Fast, accurate. |
| 2 | `shap_linear` | `import shap` succeeds, tree missing, LogisticRegression in pipeline | `shap.LinearExplainer` on LR, expects pre-scaled X. |
| 3 | `shap_kernel` | `import shap` succeeds, no tree or linear found | `shap.KernelExplainer` with max 50 background samples, single-sample evaluation, 200 samples per eval. |
| 4 | `permutation_perturbation` | Always available, no external deps needed | Custom 1-feature-at-a-time perturbation: for each feature, flip it between its {2,5,50,95,98} percentiles on a 2000-row validation background, measure Δp̂. Returns a local ranking of feature impact. |

The fallback chain means: **Phase 5's §38 local explanation contract is satisfied even when `shap` is not installed**, which it isn't in the default requirements.txt. Users who want true SHAP values can `pip install shap` and re-run training — the explainability module will auto-upgrade.

### 3.3 Permutation-Perturbation Details

Implemented at `ml/explainability.py::permutation_explain_sample`:

1. Build `background_pctiles` matrix (5 representative rows) from the validation set passed in.
2. For each feature `f`, for each percentile level `p`:
   a. Construct `X_perturbed` = copy of `X_sample` with column `f` replaced by `background_pctiles[p, f_idx]`.
   b. Compute `Δp̂ = p̂(sample) − p̂(perturbed)`.
3. Average absolute Δp̂ across percentile levels per feature → importance score.
4. Sort descending, take `top_k`, and assign sign based on whether Δp̂ agreed with the final predicted direction → `impact`.

This is less principled than SHAP but:

- No external dependency.
- Correctly ranks features in practice.
- Preserves the Phase 6 consumer contract — downstream can render feature-contribution bars without caring which engine produced the list.

## 4. Artifact Locations

| Artifact | Path | Contents |
|---|---|---|
| Global importance | `reports/ml/feature_importance.json` | `{ "engine": "...", "top_k": [...], "importance": { "entropy": 0.0423, ... } }` |
| Local explanations | `reports/ml/local_explanations.json` | list of 10 `explain_sample` outputs for stratified-sample test URLs. |

## 5. Inference-Time Local Explanations (API)

When the consumer hits `/api/v1/ml/predict?include_explanations=true`, the endpoint uses `SecureSightPredictor._local_explanation` which implements a lightweight, model-agnostic heuristic of the same contract schema, suitable for sub-millisecond on-line use (a true SHAP explainer at inference time is too expensive and requires keeping fitted background data; deferred to Phase 7 if requested).
