# Behavior feature contract

config/behavior_features.json defines the separate **8.0.0** registry. It documents 11 numeric/boolean observations: redirect_count, unique_redirect_domains, domain_transition_count, cross_domain_redirect_ratio, redirect_loop_detected, http_to_https, https_to_http, shortener_detected, js_redirect_detected, meta_refresh_detected and final_domain_changed. Missing observations are null. JS/meta flags describe static patterns, not executed navigation.

The serving model and canonical model feature schema remain **5.1.1**, with 97 aggregate fields and 59 learned URL inputs. No behavior field is inserted into its vector, no compatibility mismatch is silently ignored, and no model is retrained. Behavioral features are ML-ready future data, not evidence that the current model learned behavior. Any future model that uses them needs a new explicit schema, trained artifact and validation.

Risk/assessment config version is **6.1.0**, reflecting the bounded behavior policy and final-target integration. Explanation version is **7.1.0**, with a separate behavior registry version/hash. Historical Phase 6/7 reports describe earlier versions and remain historical evidence; their metrics are not rerun or relabeled as this phase's performance.

Risk category weights remain unchanged. Behavior adjustment is separate from seven-category base score and corroboration floors, never more than 10 effective points after score saturation. Selected behavioral contribution equals the effective adjustment; repeated/correlated chain indicators do not add again. Completeness adds a redirect stage when present; evidence coverage/confidence still describe the original weighted signal categories, with missing redirect behavior gating definitive decisions. Reason count does not equal independent risk-source count.

The current coefficients remain provisional. No final holdout was used, no thresholds were tuned and no full-pipeline accuracy guarantee follows from unit/runtime checks. Chain timings and feature values describe the observation made during that scan, not permanent website behavior.
