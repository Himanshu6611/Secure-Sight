"""Read-only frozen benchmark replay, fitted-baseline comparison and leakage audit.

Never trains/selects the serving model or changes its artifacts/test partitions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess  # nosec B404
import time
from urllib.parse import urlsplit, unquote
import numpy as np
import pandas as pd
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.metrics import classification_report, brier_score_loss
from ml.dataset import compute_file_hash
from ml.evaluation import compute_full_metrics
from ml.features import FEATURE_ORDER, URL_FEATURE_ORDER
from ml.inference import SecureSightPredictor
from quality.gates import wilson

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261009


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf8")


def partition_audit(rows, split):
    """Validate IDs/domains/labels plus URL near-duplicate keys across all splits."""
    if set(split) != {"train", "calibration", "threshold_selection", "test"}:
        raise ValueError("Frozen partition contract mismatch")
    index = rows.set_index("row_id", drop=False)
    if not index.index.is_unique or rows.url.duplicated().any():
        raise ValueError("Duplicate row/URL identity")
    seen_ids, seen_domains, seen_near = set(), set(), set()
    summary = {}
    for name, specification in split.items():
        ids = specification["row_ids"]
        if len(ids) != len(set(ids)) or set(ids) & seen_ids or not set(ids) <= set(index.index):
            raise ValueError("Split identity overlap/missing rows")
        frame = index.loc[ids]
        domains = set(frame.registrable_domain)
        if domains & seen_domains or domains != set(specification["domains"]):
            raise ValueError("Domain leakage or manifest mismatch")
        if len(frame) != specification["rows"] or {str(k): int(v) for k, v in frame.label.value_counts().items()} != {str(k): v for k, v in specification["labels"].items()}:
            raise ValueError("Split distribution mismatch")
        near = set()
        for url in frame.url:
            parsed = urlsplit(url)
            # Keep hostname: common '/' paths across unrelated hosts are not clones.
            key = (parsed.hostname, unquote(parsed.path).rstrip("/") or "/", tuple(sorted(parsed.query.split("&"))))
            near.add(hashlib.sha256(repr(key).encode()).hexdigest())
        if near & seen_near:
            raise ValueError("Near URL identity leakage")
        seen_ids.update(ids); seen_domains.update(domains); seen_near.update(near)
        summary[name] = {"rows": len(frame), "domains": len(domains), "labels": specification["labels"],
                         "unique_near_url_keys": len(near)}
    if seen_ids != set(index.index):
        raise ValueError("Partition coverage mismatch")
    return {"status": "PASS", "partitions": summary, "row_overlap": 0, "domain_overlap": 0,
            "cross_partition_near_url_overlap": 0,
            "unavailable": ["campaign identities", "capture timestamps/temporal split", "raw page/image clone similarity"]}


def select_validation_threshold(labels, probability):
    """Fixed prior training objective; exact FPR, validation only, no holdout use."""
    candidates = []
    for threshold in np.arange(.05, .96, .01):
        prediction = probability >= threshold
        tp = int(((labels == 1) & prediction).sum()); fp = int(((labels == 0) & prediction).sum())
        positives, negatives = int((labels == 1).sum()), int((labels == 0).sum())
        recall = tp / positives if positives else 0
        precision = tp / (tp + fp) if tp + fp else 0
        candidates.append({"threshold": round(float(threshold), 2), "fpr": fp / negatives if negatives else None,
                           "recall": recall, "precision": precision})
    eligible = [r for r in candidates if r["fpr"] is not None and r["fpr"] <= .01]
    if not eligible:
        raise ValueError("Validation FPR operating constraint unavailable")
    return {**max(eligible, key=lambda r: (r["recall"], r["precision"])), "partition": "threshold_selection",
            "objective": "maximum recall subject to validation FPR <= 1%"}


def calibration(labels, probability):
    bins = []
    ece = 0.0
    for i in range(10):
        mask = (probability >= i / 10) & (probability < (i + 1) / 10 if i < 9 else probability <= 1)
        count = int(mask.sum())
        predicted = float(probability[mask].mean()) if count else None
        observed = float(labels[mask].mean()) if count else None
        if count:
            ece += count / len(labels) * abs(predicted - observed)
        bins.append({"lower": i / 10, "upper": (i + 1) / 10, "samples": count,
                     "mean_probability": predicted, "phishing_fraction": observed})
    return {"brier_score": float(brier_score_loss(labels, probability)), "ece_10_equal_width": ece,
            "reliability_bins": bins, "scope": "historical test replay; not deployment calibration"}


def metrics(labels, probability, threshold, domains=None):
    if len(labels) != len(probability) or not len(labels) or not np.isfinite(probability).all() or not ((probability >= 0) & (probability <= 1)).all():
        raise ValueError("Invalid evaluation arrays")
    prediction = (probability >= threshold).astype(int)
    if len(np.unique(labels)) == 2:
        result = compute_full_metrics(labels, prediction, probability)
    else:
        # A single-class slice cannot define ROC-AUC, PR-AUC or both error rates.
        tn = int(((labels == 0) & (prediction == 0)).sum()); fp = int(((labels == 0) & (prediction == 1)).sum())
        fn = int(((labels == 1) & (prediction == 0)).sum()); tp = int(((labels == 1) & (prediction == 1)).sum())
        result = {"roc_auc": None, "pr_auc": None, "confusion_matrix": {"true_negative": tn, "false_positive": fp, "false_negative": fn, "true_positive": tp},
                  "false_positive_rate": fp / (fp + tn) if fp + tn else None,
                  "false_negative_rate": fn / (fn + tp) if fn + tp else None}
    result.update(samples=len(labels), threshold=threshold,
                  per_class=classification_report(labels, prediction, labels=[0, 1], target_names=["legitimate", "phishing"], output_dict=True, zero_division=0),
                  calibration=calibration(labels, probability))
    cm = result["confusion_matrix"]
    result["row_wilson_95"] = {"fpr": wilson(cm["false_positive"], cm["false_positive"] + cm["true_negative"]),
                               "fnr": wilson(cm["false_negative"], cm["false_negative"] + cm["true_positive"])}
    if domains is not None:
        codes, unique = pd.factorize(domains)
        cells = np.column_stack([np.bincount(codes, weights=((labels == a) & (prediction == b)), minlength=len(unique)) for a, b in [(0, 0), (0, 1), (1, 0), (1, 1)]])
        rng = np.random.default_rng(SEED)
        rates = {"fpr": [], "fnr": []}
        for _ in range(200):
            tn, fp, fn, tp = cells[rng.integers(0, len(unique), len(unique))].sum(axis=0)
            if tn + fp: rates["fpr"].append(fp / (tn + fp))
            if fn + tp: rates["fnr"].append(fn / (fn + tp))
        result["domain_bootstrap_95"] = {k: np.quantile(v, [.025, .975]).tolist() if v else None for k, v in rates.items()}
        result["bootstrap"] = {"seed": SEED, "resamples": 200, "unit": "registrable_domain", "domains": len(unique)}
    return result


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path, default=ROOT / "reports/phase14_20261009")
    args = parser.parse_args(); started = time.monotonic()
    data = ROOT / "data/v5_1_1"; bundle = ROOT / "models/v5"
    manifest = json.loads((data / "manifest.json").read_text()); split = json.loads((data / "splits.json").read_text())
    metadata = json.loads((bundle / "model_metadata.json").read_text())
    for name, expected in manifest["files"].items():
        if compute_file_hash(data / name) != expected:
            raise ValueError("Frozen dataset hash mismatch")
    if compute_file_hash(data / "splits.json") != metadata["split_sha256"] or metadata["dataset_sha256"] != manifest["source_sha256"]:
        raise ValueError("Model/dataset/split provenance mismatch")
    rows = pd.read_csv(data / "rows.csv"); features = pd.read_parquet(data / "features.parquet")
    from utils.domain_extraction import extract_domain_components
    if any(extract_domain_components(url)["normalized_registrable_domain"] != domain for url, domain in zip(rows.url, rows.registrable_domain)):
        raise ValueError("Actual URL/domain grouping mismatch")
    if any(hashlib.sha256((url + "\0" + str(label)).encode()).hexdigest() != identity for url, label, identity in zip(rows.url, rows.label, rows.row_id)):
        raise ValueError("Row identity/label provenance mismatch")
    source = ROOT / "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
    if source.exists() and compute_file_hash(source) != manifest["source_sha256"]:
        raise ValueError("Publisher source hash mismatch")
    if list(features.columns) != FEATURE_ORDER or len(features) != len(rows) or manifest["learned_features"] != URL_FEATURE_ORDER:
        raise ValueError("Feature alignment mismatch")
    if not features[URL_FEATURE_ORDER].notna().all().all() or not features.drop(columns=URL_FEATURE_ORDER).isna().all().all():
        raise ValueError("Observed/fabricated feature contract mismatch")
    audit = partition_audit(rows, split)
    row_index = {identity: i for i, identity in enumerate(rows.row_id)}
    parts = {name: np.array([row_index[k] for k in value["row_ids"]]) for name, value in split.items()}
    predictor = SecureSightPredictor()
    if predictor.load()["status"] != "OK": raise ValueError("Approved serving model unavailable")
    test_idx, selection_idx = parts["test"], parts["threshold_selection"]
    ytest = rows.iloc[test_idx].label.to_numpy(); yselection = rows.iloc[selection_idx].label.to_numpy()
    probability = predictor.model.predict_proba(features.iloc[test_idx])[:, 1]
    frozen = np.load(ROOT / "reports/remediation_20261008/training_v5_1_1/final_test_predictions.npz", allow_pickle=False)
    if not np.array_equal(frozen["row_ids"], rows.iloc[test_idx].row_id.to_numpy()) or not np.array_equal(frozen["labels"], ytest) or not np.allclose(frozen["probability"], probability, atol=1e-12, rtol=0):
        raise ValueError("Frozen prediction replay mismatch")
    comparison = {"current_calibrated_stack": metrics(ytest, probability, predictor.threshold, rows.iloc[test_idx].registrable_domain)}
    current_selection = predictor.model.predict_proba(features.iloc[selection_idx])[:, 1]
    comparison["current_calibrated_stack"]["validation_operating_point"] = metrics(yselection, current_selection, predictor.threshold)
    dummy = DummyClassifier(strategy="prior", random_state=SEED)
    dummy.fit(features.iloc[parts["train"]], rows.iloc[parts["train"]].label)
    logistic = predictor.model.calibrated_classifiers_[0].estimator.fitted_base_estimators_["logistic_regression"]
    for name, baseline in [("dummy_train_prior", dummy), ("fitted_interpretable_logistic", logistic)]:
        selected = select_validation_threshold(yselection, baseline.predict_proba(features.iloc[selection_idx])[:, 1])
        baseline_p = baseline.predict_proba(features.iloc[test_idx])[:, 1]
        comparison[name] = metrics(ytest, baseline_p, selected["threshold"], rows.iloc[test_idx].registrable_domain)
        comparison[name]["validation_operating_point"] = selected
    stack = predictor.model.calibrated_classifiers_[0].estimator
    # Verify fitted training medians against train-only rows, not full data.
    fitted_medians = stack.fitted_base_estimators_["logistic_regression"].named_steps["preprocess"].named_steps["impute"].statistics_
    if not np.allclose(fitted_medians, features.iloc[parts["train"]][URL_FEATURE_ORDER].median().to_numpy()):
        raise ValueError("Train-only preprocessing mismatch")
    if any(fold["domain_overlap"] for fold in stack.fold_audit_): raise ValueError("OOF leakage")
    slices = {}
    test_features = features.iloc[test_idx]
    for name, mask in {"encoded": test_features.encoded_ratio.to_numpy() > 0,
                       "idn": (test_features.punycode_detected.to_numpy() > 0) | (test_features.unicode_detected.to_numpy() > 0),
                       "http": test_features.is_https.to_numpy() == 0,
                       "has_query": test_features.query_len.to_numpy() > 0,
                       "long_url_100_plus": test_features.url_len.to_numpy() >= 100}.items():
        slices[name] = metrics(ytest[mask], probability[mask], predictor.threshold) if mask.any() else {"status": "UNAVAILABLE", "samples": 0}
    raw_probability = stack.predict_proba(features.iloc[test_idx])[:, 1]
    write(args.output / "calibration_comparison.json", {"raw_stack": calibration(ytest, raw_probability),
          "sigmoid_stack": calibration(ytest, probability), "fit_partition": "calibration",
          "evaluation_partition": "frozen_test_replay", "new_calibration_fit": False})
    audit.update(prediction_replay="PASS", preprocessing_train_medians="PASS", grouped_oof=stack.fold_audit_,
                 source_checksum="PASS" if source.exists() else "UNAVAILABLE", actual_domain_recomputation="PASS",
                 target_derived_features="Only URL_FEATURE_ORDER; publisher similarity/filename/label features excluded",
                 dataset_license="CC BY 4.0 per UCI source; local retrieval timestamp not recorded")
    write(args.output / "leakage_audit.json", audit)
    write(args.output / "model_comparison.json", comparison)
    write(args.output / "robustness_slices.json", slices)
    environment = {"python": platform.python_version(), "sklearn": sklearn.__version__, "numpy": np.__version__, "seed": SEED,
                   "git_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip(),  # nosec B603 B607
                   "working_tree": "dirty; source hashes separately recorded", "dataset_version": manifest["dataset_version"],
                   "model_version": metadata["model_version"], "schema_version": metadata["feature_schema_version"],
                   "dataset_sha256": manifest["source_sha256"], "split_sha256": metadata["split_sha256"],
                   "model_sha256": compute_file_hash(bundle / "model.pkl"), "elapsed_seconds": round(time.monotonic() - started, 3),
                   "scope": "Historical frozen holdout replay; previously inspected test data, not new model selection or independent prospective validation"}
    write(args.output / "evaluation_environment.json", environment)
    snapshot = {}
    for directory in ("app", "utils", "ml", "quality", "tests", "config", ".github"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and path.suffix in {".py", ".js", ".json", ".yml", ".yaml"} and "__pycache__" not in path.parts:
                snapshot[path.relative_to(ROOT).as_posix()] = compute_file_hash(path)
    for path in ROOT.glob("requirements*.txt"):
        snapshot[path.name] = compute_file_hash(path)
    write(args.output / "source_snapshot.json", snapshot)
    print(json.dumps({"samples": len(ytest), "models": list(comparison), "replay": "PASS", "elapsed_seconds": environment["elapsed_seconds"]}), flush=True)


if __name__ == "__main__": main()
