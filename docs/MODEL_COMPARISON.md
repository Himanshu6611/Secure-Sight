# Model comparison

Same frozen train/calibration/threshold-selection/test partitions. Current stack kept at frozen 0.93; existing train-fitted logistic baseline reused. Dummy prior fitted only to train labels. Baseline thresholds selected on validation under FPR <=1%, never on test. No winner selected or model promoted.

| Model | Threshold | Accuracy | Precision | Recall | F1 | FPR | FNR | ROC AUC | PR AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| current_calibrated_stack | 0.930000 | 0.985290 | 0.993950 | 0.971917 | 0.982810 | 0.004511 | 0.028083 | 0.992876 | 0.994122 |
| dummy_train_prior | 0.430000 | 0.567334 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 1.000000 | 0.500000 | 0.432666 |
| fitted_interpretable_logistic | 0.610000 | 0.983968 | 0.992159 | 0.970617 | 0.981270 | 0.005850 | 0.029383 | 0.991691 | 0.993455 |

Dummy becomes reject-all at the validation FPR constraint; zero FPR with 100% FNR is not useful detection. Current stack has modest historical gains over logistic, not a promise of generalization. Preserve existing serving and original baseline artifacts; full metrics, CIs and calibration remain machine-readable.
