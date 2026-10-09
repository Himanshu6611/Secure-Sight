# Actual model explainability

The serving predictor uses trusted artifact version 5.1.1: calibrated URL lexical classification with embedded preprocessing. Although the aggregate feature schema has 97 fields, the actual learned URL inputs number 59; domain and static webpage evidence are scored separately. A page/password feature must not be described as a learned model driver.

For a local explanation, the existing predictor replaces each URL input individually with the actual training median saved in model metadata and evaluates the calibrated model in one batch. Signed impact is original probability minus perturbed probability. Positive means the current value raises the model estimate relative to that median; negative means it lowers it. The output records feature name/value, human label, direction, magnitude, baseline value and perturbed probability.

This is **training-median feature perturbation sensitivity**. It is not SHAP, statistical permutation importance, causal attribution or an additive decomposition. Correlated features and median substitutions can make effects difficult to interpret. Impacts must not be added to the Phase 6 risk score. Neutral impacts remain neutral; missing impacts are not replaced with heuristic feature weights.

The Phase 7 translator requires matching model/schema versions and assessment probability, validated-model provenance, the actual supported method, finite values, an allowlisted URL feature, consistent direction and numerically consistent measured delta. Missing/invalid local evidence returns UNAVAILABLE with an explicit warning. Missing median metadata or explanation computation failure preserves an otherwise valid model prediction and returns unavailable explanation status.

Global explainability remains an offline concern. Existing ml/explainability.py provides native tree/global permutation helpers and optional SHAP; these are not run on every request. Legacy reports/ml/feature_importance.json lacks current-serving-model provenance and is not exposed as a current local explanation. Phase 7 deliberately uses the appropriate existing measured local method rather than labeling native/global feature importance as a per-URL contribution. No SHAP dependency was added or model retrained.

Tests independently rerun each reported median substitution and compare the resulting probability to the recorded perturbation. Controlled latency is reported separately for model explanation computation, translation and serialization.
