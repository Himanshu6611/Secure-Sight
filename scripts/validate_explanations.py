"""Offline fixture replay and measured timings; no accuracy benchmark claim."""
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.explanation.test_engine import observations
from app.explanations.engine import ExplanationEngine
from app.risk.engine import RiskScoringEngine
from ml.features import aggregate_feature_dict
from ml.inference import SecureSightPredictor


def timing(values):
    ordered = sorted(values)
    return {"median_ms": round(statistics.median(ordered), 6), "p95_ms": round(ordered[int(.95*(len(ordered)-1))], 6)}


def main():
    engine, risk, predictor = ExplanationEngine(), RiskScoringEngine(), SecureSightPredictor()
    assert predictor.load()["status"] == "OK"
    context = observations(False, .02, "SAFE")
    vector = aggregate_feature_dict(context["url_features"], context["domain_intelligence"], context["web_intelligence"])
    model_times = []
    for _ in range(25):
        prediction = predictor.predict(vector)
        assert prediction["explanation_status"] == "AVAILABLE"
        model_times.append(prediction["explanation_latency_ms"])
    context["ml_result"] = prediction
    assessment = risk.calculate(context)
    samples, scoring_times, serialization_times = [], [], []
    expected = engine.explain(assessment, prediction, context["web_intelligence"])
    for _ in range(500):
        start = time.perf_counter()
        result = engine.explain(assessment, prediction, context["web_intelligence"])
        scoring_times.append((time.perf_counter()-start)*1000)
        assert result == expected
        start = time.perf_counter()
        serialized = json.dumps(result, allow_nan=False)
        serialization_times.append((time.perf_counter()-start)*1000)
        samples.append(len(serialized.encode()))
    report = {"explanation_version": expected["explanation_version"], "registry_sha256": expected["registry_sha256"],
        "scope": "Controlled existing evidence fixtures; not real-world detection accuracy", "replays": 500,
        "deterministic": True, "explanation_latency": timing(scoring_times),
        "model_local_explanation_latency": timing(model_times), "serialization_latency": timing(serialization_times),
        "serialized_bytes": max(samples), "example": expected}
    folder = Path("reports/phase7_20261008")
    folder.mkdir(parents=True, exist_ok=True)
    (folder/"validation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "example"}, indent=2))


if __name__ == "__main__":
    main()
