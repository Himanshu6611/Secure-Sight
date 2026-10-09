"""Evaluate only frozen development rows; no DNS/HTTP, no training, no test tuning."""
import sys
import json
import time
import hashlib
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.risk.engine import RiskScoringEngine
from app.risk.signals import collect_signals
from app.risk.aggregation import aggregate
from app.risk.confidence import confidence
from ml.inference import SecureSightPredictor
from ml.features import URL_FEATURE_ORDER
from ml.dataset import compute_file_hash
from utils.url_indicators import analyze_url_indicators

OUT=ROOT/"reports/phase6_20261008"
OUT.mkdir(parents=True,exist_ok=True)
data=ROOT/"data/v5_1_1"
split=json.loads((data/"splits.json").read_text())
development_ids=set(split["threshold_selection"]["row_ids"])
rows=pd.read_csv(data/"rows.csv")
index=np.flatnonzero(rows.row_id.isin(development_ids).to_numpy())
development=rows.iloc[index].reset_index(drop=True)
assert len(development)==len(development_ids)
assert not set(development.row_id)&set(split["test"]["row_ids"])
features=pd.read_parquet(data/"features.parquet").iloc[index].reset_index(drop=True)
predictor=SecureSightPredictor()
assert predictor.load()["status"]=="OK"
# Actual model batch probabilities; contexts truthfully lack web/domain snapshots.
probabilities=predictor.model.predict_proba(features)[:,1]
engine=RiskScoringEngine()
configuration=engine.config
results=[];latencies=[];confidence_latencies=[];serialization_latencies=[]
for i,row in development.iterrows():
    lexical=features.loc[i,URL_FEATURE_ORDER].to_dict()
    validation_vector={key:(value if value>=0 else None) for key,value in lexical.items()}
    valid,_,code,_=predictor._validate_feature_vector(validation_vector)
    ml_result={"status":"OK","probability":float(probabilities[i]),"model_version":"5.1.1",
        "feature_schema_version":"5.1.1","model_validated":True,"calibration_method":predictor.calibration_method} if valid else {
        "status":code,"probability":None,"prediction":None}
    ctx={"url_features":lexical,
         "url_indicators":analyze_url_indicators(row.url,lexical)["indicators"],
         "domain_intelligence":{},"web_intelligence":{},
         "ml_result":ml_result,
         "feature_schema_version":"5.1.1","scheme":row.url.split(":",1)[0]}
    begin=time.perf_counter();result=engine.calculate(ctx);latencies.append((time.perf_counter()-begin)*1000)
    assert result["status"]=="OK", result
    assert result["verdict"] not in {"LEGITIMATE","PHISHING"}, "Insufficient evidence yielded a definitive verdict"
    if i<1000:
        signals,stages,flags=collect_signals(ctx,configuration)
        _,_,coverage,_,signals=aggregate(signals,configuration)
        begin=time.perf_counter();confidence(signals,coverage,flags,configuration);confidence_latencies.append((time.perf_counter()-begin)*1000)
        begin=time.perf_counter();json.dumps(result,allow_nan=False);serialization_latencies.append((time.perf_counter()-begin)*1000)
    results.append({"row_id":row.row_id,"label":int(row.label),"risk_score":result["risk_score"],
        "confidence":result["confidence"],"coverage":result["evidence_coverage"],"verdict":result["verdict"]})
    if (i+1)%2000==0:print(f"Development rows assessed: {i+1}",flush=True)
frame=pd.DataFrame(results)
frame.to_csv(OUT/"development_assessments.csv",index=False)

def distribution(values):
    return {str(q):float(np.percentile(values,q)) for q in (0,10,25,50,75,90,100)}

def latency(values):
    return {"samples":len(values),"median_ms":float(np.median(values)),"p95_ms":float(np.percentile(values,95))}
defined=frame.verdict.isin(["LEGITIMATE","PHISHING"])
metrics=None
if defined.any():
    y=frame.loc[defined,"label"];pred=frame.loc[defined,"verdict"].eq("PHISHING").astype(int)
    metrics={"accuracy":accuracy_score(y,pred),"precision":precision_score(y,pred,zero_division=0),
        "recall":recall_score(y,pred,zero_division=0),"f1":f1_score(y,pred,zero_division=0)}
buckets=[]
for low,high in ((0,20),(20,40),(40,60),(60,80),(80,100)):
    chosen=(frame.confidence>=low)&((frame.confidence<high) if high<100 else (frame.confidence<=high))
    comparable=chosen&defined
    buckets.append({"low":low,"high":high,"samples":int(chosen.sum()),"definitive_verdict_samples":int(comparable.sum()),
        "actual_correctness":float(frame.loc[comparable,"verdict"].eq("PHISHING").astype(int).eq(frame.loc[comparable,"label"]).mean()) if comparable.any() else None})
report={
    "assessment_version":"6.0.0","scoring_config_version":engine.config["version"],
    "scoring_config_sha256":engine.calculate(ctx)["scoring_config_sha256"],
    "partition":"threshold_selection (development only)","samples":len(frame),
    "dataset_manifest_sha256":compute_file_hash(data/"manifest.json"),
    "split_sha256":compute_file_hash(data/"splits.json"),
    "source_sha256":json.loads((data/"manifest.json").read_text())["source_sha256"],
    "analysis_scope":"Observed lexical features and calibrated URL model only; no domain/HTML observations were fabricated",
    "configuration_tuned":False,"final_test_used":False,
    "verdict_counts":frame.verdict.value_counts().to_dict(),"definitive_coverage":float(defined.mean()),
    "definitive_verdict_metrics":metrics,"false_positive_rate":None,"false_negative_rate":None,
    "risk_by_source_label":{str(label):distribution(group.risk_score) for label,group in frame.groupby("label")},
    "risk_distribution":distribution(frame.risk_score),"confidence_distribution":distribution(frame.confidence),
    "confidence_buckets":buckets,"risk_zero_fraction":float(frame.risk_score.eq(0).mean()),
    "risk_hundred_fraction":float(frame.risk_score.eq(100).mean()),
    "scoring_latency":latency(latencies),"confidence_latency":latency(confidence_latencies),
    "serialization_latency":latency(serialization_latencies),
    "validation_status":"PARTIAL_OBSERVATION_EVALUATION_ONLY",
    "limitations":["Representative full-intelligence labeled snapshots are unavailable",
        "Abstentions are not counted as correct classifications","No calibrated-confidence or public-readiness claim"]
}
(OUT/"validation_report.json").write_text(json.dumps(report,indent=2,allow_nan=False),encoding="utf8")
print(json.dumps(report,indent=2),flush=True)
