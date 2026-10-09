"""Reproducible corrected-label training; no network and no fabricated web evidence.

Only observed URL features are learned. Domain/HTML evidence is a separately
named decision policy until a representative labeled snapshot corpus exists.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import sys
import time
import datetime
import platform
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.model_selection import StratifiedGroupKFold, GridSearchCV, train_test_split
from sklearn.calibration import CalibratedClassifierCV
from ml.features import FEATURE_ORDER, URL_FEATURE_ORDER, FEATURE_SCHEMA_VERSION, align_features_df
from ml.dataset import clean_source_dataset, split_dataset_by_domain_group, compute_file_hash
from ml.ensemble import StackingEnsembleClassifier
from ml.evaluation import compute_full_metrics, threshold_analysis, compute_roc_curve_data, compute_pr_curve_data
from utils.url_features import extract_advanced_url_features

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = ROOT / "reports/remediation_20261008/training_v5_1_1"
DATA = ROOT / "data/v5_1_1"
MODEL = ROOT / "models/v5"
SEED = 20261008


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, default=str, allow_nan=False), encoding="utf8")


def log(message):
    print(message, flush=True)


def preprocessing(scale=False):
    steps = [("observed_url_columns", ColumnTransformer([("url", "passthrough", URL_FEATURE_ORDER)], remainder="drop")),
             ("impute", SimpleImputer(strategy="median"))]
    if scale:
        steps.append(("scale", StandardScaler()))
    return Pipeline(steps)


def estimator(model, scale=False):
    return Pipeline([("preprocess", preprocessing(scale)), ("classifier", model)])


def generate_dataset():
    source = ROOT / "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
    expected_hash = compute_file_hash(source)
    version_path = DATA / "manifest.json"
    if version_path.exists():
        manifest = json.loads(version_path.read_text())
        if manifest.get("source_sha256") == expected_hash and manifest.get("feature_schema_version") == FEATURE_SCHEMA_VERSION:
            for filename, expected in manifest.get("files", {}).items():
                if compute_file_hash(DATA / filename) != expected:
                    raise RuntimeError("Frozen dataset checksum mismatch")
            log("Reusing frozen corrected dataset")
            return pd.read_csv(DATA / "rows.csv"), pd.read_parquet(DATA / "features.parquet"), manifest
        raise RuntimeError("Dataset version already exists with different provenance; choose a new version")
    log("Mapping publisher labels: source 1 legitimate -> target 0 legitimate")
    rows, manifest = clean_source_dataset(pd.read_csv(source, usecols=["URL", "label"]), source="phiusiil")
    features = []
    for i, url in enumerate(rows.url):
        features.append(extract_advanced_url_features(url))
        if (i+1) % 10000 == 0:
            log(f"Features: {i+1}/{len(rows)}")
    X = align_features_df(pd.DataFrame(features))
    if X[URL_FEATURE_ORDER].isna().any().any():
        raise RuntimeError("Observed lexical features contain missing values")
    DATA.mkdir(parents=True, exist_ok=True)
    rows.to_csv(DATA / "rows.csv", index=False)
    X.to_parquet(DATA / "features.parquet", index=False)
    manifest.update(source_sha256=expected_hash, feature_schema_version=FEATURE_SCHEMA_VERSION,
                    feature_order=FEATURE_ORDER, learned_features=URL_FEATURE_ORDER,
                    unobserved_features=[f for f in FEATURE_ORDER if f not in URL_FEATURE_ORDER],
                    scope="No DNS/TLS/HTML data was fabricated or fetched for training",
                    files={name: compute_file_hash(DATA/name) for name in ["rows.csv", "features.parquet"]})
    dump(version_path, manifest)
    return rows, X, manifest


def calibration_ece(y, probabilities):
    assignments = np.clip(np.digitize(probabilities, np.linspace(0, 1, 11)) - 1, 0, 9)
    return float(sum(np.mean(assignments == b) * abs(np.mean(y[assignments == b]) - np.mean(probabilities[assignments == b]))
                     for b in range(10) if np.any(assignments == b)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    RUN.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    rows, X, manifest = generate_dataset()
    train, validation, test = split_dataset_by_domain_group(rows, random_state=SEED)
    # Calibration and threshold selection get separate domain partitions.
    majority = validation.groupby("registrable_domain").label.mean().ge(.5).astype(int)
    cal_domains, threshold_domains = train_test_split(majority.index.to_numpy(), test_size=.5,
        stratify=majority.values, random_state=SEED+2)
    calibration = validation[validation.registrable_domain.isin(cal_domains)].copy()
    selection = validation[validation.registrable_domain.isin(threshold_domains)].copy()
    partitions = {"train":train, "calibration":calibration, "threshold_selection":selection, "test":test}
    groups = {name:set(frame.registrable_domain) for name,frame in partitions.items()}
    for i,name in enumerate(groups):
        for other in list(groups)[i+1:]:
            if groups[name] & groups[other]:
                raise RuntimeError("Domain partition leakage")
    split = {name: dict(row_ids=frame.row_id.tolist(), domains=sorted(groups[name]),
                       rows=len(frame), labels=frame.label.value_counts().to_dict()) for name,frame in partitions.items()}
    split_path = DATA / "splits.json"
    if split_path.exists() and json.loads(split_path.read_text()) != json.loads(json.dumps(split, default=str)):
        raise RuntimeError("Frozen split cannot be overwritten")
    dump(split_path, split)
    index = dict(zip(rows.row_id, range(len(rows))))
    def matrix(frame):
        return X.iloc[[index[k] for k in frame.row_id]].reset_index(drop=True)
    Xtrain, ytrain = matrix(train), train.label.reset_index(drop=True)
    # Dataset-derived reputation is limited to training domains, and excludes any mixed-label host.
    hosts = train.url.map(lambda u: __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(u).hostname)
    counts = pd.DataFrame({"host":hosts, "label":train.label}).groupby("host").label.agg(["min", "count"])
    blacklist = sorted(counts[(counts['min']==1)&(counts['count']>=2)].index)
    (ROOT/"data/blacklist.csv").write_text("domain\n"+"\n".join(blacklist)+"\n", encoding="utf8")
    dump(ROOT/"data/metadata/blacklist_metadata.json",dict(source="Historical corrected benchmark, not a live threat feed",
         partition="train_only", exact_hosts=True, mixed_label_hosts_excluded=True, domains=len(blacklist), sha256=compute_file_hash(ROOT/'data/blacklist.csv'), source_hash=manifest['source_sha256']))
    if args.prepare_only:
        return
    # Tune on a deterministic training-only subset; preprocessing remains inside each fold.
    tune = train.sample(n=min(30000,len(train)), random_state=SEED).reset_index(drop=True)
    Xtune, ytune = matrix(tune), tune.label
    cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED)
    bases = {
        "logistic_regression": estimator(LogisticRegression(max_iter=700,class_weight="balanced",random_state=SEED), True),
        "random_forest": estimator(RandomForestClassifier(n_estimators=100,max_depth=22,min_samples_leaf=2,
                                     class_weight="balanced",n_jobs=2,random_state=SEED)),
        "extra_trees": estimator(ExtraTreesClassifier(n_estimators=100,max_depth=22,min_samples_leaf=2,
                                 class_weight="balanced",n_jobs=2,random_state=SEED))}
    grids = {"logistic_regression":{"classifier__C":[.1,1.]},
             "random_forest":{"classifier__max_depth":[16,22]}, "extra_trees":{"classifier__max_depth":[16,22]}}
    comparison = {}
    for name, model in bases.items():
        log("Grouped, fold-local tuning: "+name)
        search=GridSearchCV(model,grids[name],cv=cv,scoring="roc_auc",n_jobs=1,error_score="raise")
        search.fit(Xtune,ytune,groups=tune.registrable_domain.to_numpy())
        bases[name]=search.best_estimator_
        comparison[name]=dict(best_params=search.best_params_,cv_auc=float(search.best_score_),
            cv_std=float(search.cv_results_["std_test_score"][search.best_index_]), tuning_rows=len(tune), cv="StratifiedGroupKFold")
    log("Training grouped OOF stack with fold-local pipelines")
    ensemble=StackingEnsembleClassifier(bases,n_folds=3,random_state=SEED)
    ensemble.fit(Xtrain,ytrain,groups=train.registrable_domain.to_numpy())
    # Calibration never trains on threshold-selection or test rows.
    log("Calibrating on separate calibration domains")
    calibrated=CalibratedClassifierCV(ensemble,method="sigmoid",cv="prefit")
    calibrated.fit(matrix(calibration),calibration.label)
    selection_proba=calibrated.predict_proba(matrix(selection))[:,1]
    thresholds=threshold_analysis(selection.label.to_numpy(),selection_proba,thresholds=np.arange(.05,.96,.01).tolist())
    eligible=[item for item in thresholds if item['fpr']<=.01]
    chosen=max(eligible or thresholds,key=lambda item:(item['recall'],item['precision'])) if eligible else max(thresholds,key=lambda item:item['f1'])
    chosen.update(selection_partition="threshold_selection", objective="maximize recall subject to observed validation FPR <= 1%", fpr_constraint_met=bool(eligible))
    log("One final evaluation on frozen test domains")
    Xtest=matrix(test)
    testproba=calibrated.predict_proba(Xtest)[:,1]
    metrics=compute_full_metrics(test.label.to_numpy(),(testproba>=chosen['threshold']).astype(int),testproba)
    metrics.update(samples=len(test),threshold_used=chosen['threshold'],target_meaning="1 phishing; 0 legitimate",
                   ece=calibration_ece(test.label.to_numpy(),testproba), scope="URL lexical model; historical benchmark, not a current public-web guarantee")
    np.savez_compressed(RUN/"final_test_predictions.npz",row_ids=test.row_id.to_numpy(dtype=str),labels=test.label.to_numpy(),probability=testproba)
    # Preserve previous invalid artifacts for investigation, then publish a complete local bundle.
    if MODEL.exists() and not (ROOT/"models/legacy_v5_invalid_20261008").exists():
        shutil.copytree(MODEL,ROOT/"models/legacy_v5_invalid_20261008")
    bundle=ROOT/"models/v5_1_1_staging"
    bundle.mkdir(parents=True,exist_ok=True)
    joblib.dump(calibrated,bundle/"model.pkl",compress=3)
    # The full model owns the fitted per-base preprocessing; this artifact describes its input selector.
    joblib.dump(ensemble.fitted_base_estimators_["logistic_regression"].named_steps['preprocess'],bundle/"preprocessor.pkl",compress=3)
    dump(bundle/"feature_schema.json",dict(feature_schema_version=FEATURE_SCHEMA_VERSION,feature_order=FEATURE_ORDER,
                                         n_features=len(FEATURE_ORDER),required_features=URL_FEATURE_ORDER))
    dump(bundle/"threshold.json",chosen)
    dump(bundle/"metrics.json",metrics)
    metadata=dict(model_version="5.1.1",feature_schema_version=FEATURE_SCHEMA_VERSION,
        label_mapping={"0":"legitimate","1":"phishing"},environment={"scikit_learn_version":sklearn.__version__,"python_version":platform.python_version()},
        preprocessing_embedded=True,calibration={"method":"sigmoid","partition":"calibration","samples":len(calibration)},
        training_feature_medians=Xtrain[URL_FEATURE_ORDER].median().to_dict(), learned_features=URL_FEATURE_ORDER,
        evidence_policy="Domain/HTML findings are separate observed evidence, not learned classifier contributions",
        model_type="grouped_oof_stacking_lr_rf_extra_trees",random_seed=SEED,dataset_sha256=manifest['source_sha256'],
        split_sha256=compute_file_hash(split_path),split_rows={k:len(v) for k,v in partitions.items()},
        final_test_evaluations=1,final_test_used_for_tuning=False,
        limitations=["Same historical source benchmark was used by prior versions; external temporal holdout still required",
                     "No representative labeled raw HTML/TLS/registration corpus is available; optional evidence not claimed as ML training"],
        training_date=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        artifact_sha256={name:compute_file_hash(bundle/name) for name in ["model.pkl","preprocessor.pkl","threshold.json","feature_schema.json"]})
    dump(bundle/"model_metadata.json",metadata)
    MODEL.mkdir(parents=True,exist_ok=True)
    # Stop app/reload models before serving this bundle; metadata is copied last.
    for name in ["model.pkl","preprocessor.pkl","feature_schema.json","threshold.json","metrics.json","model_metadata.json"]:
        shutil.copy2(bundle/name,MODEL/name)
    dump(RUN/"model_comparison.json",comparison)
    dump(RUN/"threshold_analysis.json",thresholds)
    dump(RUN/"evaluation_report.json",metrics)
    dump(RUN/"roc_curve.json",compute_roc_curve_data(test.label.to_numpy(),testproba))
    dump(RUN/"pr_curve.json",compute_pr_curve_data(test.label.to_numpy(),testproba))
    dump(RUN/"fold_audit.json",ensemble.fold_audit_)
    dump(ROOT/"data/metadata/dataset_manifest.json",manifest)
    dump(ROOT/"data/metadata/label_definition.json",dict(target_column="label",encoding={"0":"legitimate","1":"phishing"},source_conversion="PhiUSIIL: target=1-source"))
    dump(ROOT/"data/metadata/dataset_hash.json",dict(dataset_version="5.1.1",files={str(DATA.relative_to(ROOT)/f):dict(sha256=compute_file_hash(DATA/f),size_bytes=(DATA/f).stat().st_size) for f in ["rows.csv","features.parquet","splits.json"]}))
    log(json.dumps(metrics,indent=2))
    log(f"Training completed in {time.perf_counter()-start:.1f}s")


if __name__=="__main__":
    main()
