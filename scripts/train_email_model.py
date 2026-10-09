#!/usr/bin/env python3
"""Train an exploratory email model using sender/message-grouped evaluation.

The emitted model is a research candidate only. SecureSight does not currently
load it in the production email service.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FEATURES_PATH = ROOT / "data/email_features.parquet"
MANIFEST_PATH = ROOT / "data/email_manifest.json"
REPORT_DIR = ROOT / "reports/email_model_research"
MODEL_DIR = ROOT / "models/email_staging"
SEED = 20261009


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main():
    if not FEATURES_PATH.exists() or not MANIFEST_PATH.exists():
        raise SystemExit("Rebuild grouped email features first: python scripts/preprocess_emails.py")
    frame = pd.read_parquet(FEATURES_PATH)
    required = {"label", "source_id", "group_id"}
    if not required <= set(frame.columns):
        raise SystemExit("Email feature file predates grouped provenance; rerun scripts/preprocess_emails.py")
    feature_columns = [name for name in frame.columns if name not in required]
    if not feature_columns or not all(pd.api.types.is_numeric_dtype(frame[name]) for name in feature_columns):
        raise SystemExit("Email model input must contain only numeric engineered features")
    if frame[feature_columns].isna().any().any() or frame["label"].isna().any() or frame["group_id"].isna().any():
        raise SystemExit("Email feature file has missing model data or identity metadata")
    if not set(frame.label.unique()) <= {0, 1}:
        raise SystemExit("Email labels must be exactly 0 (legitimate) or 1 (phishing)")

    from ml.email_dataset import email_dataset_audit, grouped_email_partitions
    from ml.email_training import candidate_models, choose_threshold, evaluate_binary
    audit = email_dataset_audit(frame, feature_columns)
    conflict_mask = frame.groupby("group_id")["label"].transform("nunique") > 1
    quarantined_rows = int(conflict_mask.sum())
    quarantined_groups = int(frame.loc[conflict_mask, "group_id"].nunique())
    audit["training_exclusions"] = {
        "reason": "conflicting labels within an exact-message/sender identity group",
        "rows": quarantined_rows, "groups": quarantined_groups,
        "policy": "exclude every row in an ambiguous group before splitting or fitting",
    }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "dataset_audit.json").write_text(json.dumps(audit, indent=2, allow_nan=False), encoding="utf-8")

    frame = frame.loc[~conflict_mask].reset_index(drop=True)
    if set(frame.label.unique()) != {0, 1}:
        raise SystemExit("After quarantining conflicting groups, both label classes are required")

    labels = frame.label.to_numpy(dtype=int)
    groups = frame.group_id.astype(str).to_numpy()
    partitions = grouped_email_partitions(labels, groups, SEED)
    partition_manifest = {name: {"samples": len(rows), "groups": len(set(groups[rows])),
                                 "class_counts": {str(k): int(v) for k, v in pd.Series(labels[rows]).value_counts().sort_index().items()}}
                         for name, rows in partitions.items()}
    seen_groups = set()
    for name, rows in partitions.items():
        current = set(groups[rows])
        if seen_groups & current:
            raise SystemExit(f"Grouped identity leakage in {name}")
        seen_groups.update(current)

    X = frame[feature_columns].astype(float)
    fit_rows = partitions["fit"]
    cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED)
    comparisons = {}
    candidates = candidate_models(SEED)
    for name, (estimator, grid) in candidates.items():
        search = GridSearchCV(estimator, grid, scoring="roc_auc", cv=cv, n_jobs=1,
                              error_score="raise", refit=True)
        search.fit(X.iloc[fit_rows], labels[fit_rows], groups=groups[fit_rows])
        candidates[name] = (search.best_estimator_, grid)
        comparisons[name] = {"grouped_cv_auc": float(search.best_score_),
                             "grouped_cv_std": float(search.cv_results_["std_test_score"][search.best_index_]),
                             "best_params": search.best_params_, "cv": "StratifiedGroupKFold(3)"}

    selected_name = max(comparisons, key=lambda name: (comparisons[name]["grouped_cv_auc"], name))
    base_model = candidates[selected_name][0]
    calibration_rows = partitions["calibration"]
    calibrated = CalibratedClassifierCV(base_model, method="sigmoid", cv="prefit")
    calibrated.fit(X.iloc[calibration_rows], labels[calibration_rows])

    threshold_rows = partitions["threshold_selection"]
    threshold_probabilities = calibrated.predict_proba(X.iloc[threshold_rows])[:, 1]
    threshold = choose_threshold(labels[threshold_rows], threshold_probabilities)
    test_rows = partitions["test"]
    test_probabilities = calibrated.predict_proba(X.iloc[test_rows])[:, 1]
    test_metrics = evaluate_binary(labels[test_rows], test_probabilities, threshold["threshold"])

    model_path = MODEL_DIR / "email_model_research.pkl"
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(calibrated, model_path, compress=3)
    model_sha256 = digest(model_path)
    metadata = {
        "status": "RESEARCH_CANDIDATE_NOT_CONNECTED_TO_SERVING",
        "model_type": selected_name, "model_version": "email-research-v1",
        "feature_schema": feature_columns, "label_mapping": {"0": "legitimate", "1": "phishing"},
        "dataset_sha256": digest(FEATURES_PATH), "dataset_manifest_sha256": digest(MANIFEST_PATH),
        "model_sha256": model_sha256,
        "split_seed": SEED, "partitions": partition_manifest, "group_overlap": 0,
        "quarantined_conflict_rows": quarantined_rows, "quarantined_conflict_groups": quarantined_groups,
        "model_selection": comparisons, "selected_model": selected_name,
        "calibration": {"method": "sigmoid", "partition": "calibration"},
        "threshold": threshold, "held_out_test": test_metrics,
        "environment": {"python": sys.version.split()[0], "scikit_learn": sklearn.__version__},
        "limitations": [
            "No collection-time split or campaign identities are available.",
            "Group split uses exact normalized messages and sender identity; unseen-source generalization is not established.",
            "Inputs are eight engineered aggregate features; this is not a text-language model.",
            "Source license and original label provenance require independent review.",
            "Candidate is not loaded by the serving email pipeline and is not an accuracy or release claim.",
        ],
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(metadata, MODEL_DIR / "email_model_research_metadata.pkl", compress=3)
    (REPORT_DIR / "evaluation_report.json").write_text(json.dumps(metadata, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({"status": metadata["status"], "selected_model": selected_name,
                      "held_out_test": test_metrics, "report": str(REPORT_DIR / "evaluation_report.json")}, indent=2))


if __name__ == "__main__":
    main()
