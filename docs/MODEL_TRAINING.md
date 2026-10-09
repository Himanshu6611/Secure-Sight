# Corrected model training

Run python -m ml.corrected_training in the pinned Python 3.12/scikit-learn 1.5.1 environment with the trusted PhiUSIIL CSV in data/raw. Active entry points delegate to this pipeline; the previous direct training workflow is retired.

1. Convert source labels explicitly and preserve URL identity.
2. Generate actual 59-field lexical vectors; record 38 optional fields as NaN.
3. Freeze train, calibration, threshold-selection and test domain groups/row IDs.
4. Tune LR/RF/ExtraTrees with StratifiedGroupKFold; fit preprocessing within each fold.
5. Fit grouped OOF stack and sigmoid calibration on separate calibration domains.
6. Select threshold on threshold-selection domains: maximize recall subject to observed FPR <=1%.
7. Evaluate frozen test once per version; save predictions and provenance.
8. Validate and provision the complete trusted bundle, then restart the app.

Versioned data is data/v5_1_1. Source, processed-file, split and artifact hashes are recorded. Changes require a new version; frozen data with mismatched checksums is refused. Historical source testing does not replace a fresh external temporal holdout. Learned URL scope is explicit.
