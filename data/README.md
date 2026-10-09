# Data versions

## Dataset attribution

The active URL training dataset is derived from the PhiUSIIL Phishing URL (Website) Dataset by Arvind Prasad and Shalini Chandra (2024), UCI Machine Learning Repository, dataset 967, DOI: https://doi.org/10.1016/j.cose.2023.103545. The upstream dataset is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0): https://creativecommons.org/licenses/by/4.0/. SecureSight's version includes label normalization, URL canonicalization, feature extraction, and grouped train/calibration/threshold/test splits. Credit the original authors and UCI when redistributing these derived artifacts.

Source record: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

Active URL training data: v5_1_1/rows.csv and v5_1_1/features.parquet, manifest.json and splits.json. Publisher labels are explicitly inverted to project 0 legitimate / 1 phishing.

cleaned.csv has been regenerated with corrected labels for compatibility. The unversioned features.parquet is a legacy 11-field artifact and is not read by the corrected pipeline or scan service. v5_1 is the first corrected experiment retained for investigation; its www shortcut bias was found in independent development smoke checks and fixed in v5_1_1.

Do not use legacy processed data/model scores as current benchmark evidence. Raw publisher CSV is retained untouched.
