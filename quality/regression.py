"""Preserve known model failures without hiding them or tuning serving artifacts."""
import json
from pathlib import Path
from ml.inference import SecureSightPredictor
from utils.url_features import extract_advanced_url_features


def main():
    root = Path(__file__).resolve().parents[1]
    corpus = json.loads((root / "tests/fixtures/quality/regression_cases.json").read_text(encoding="utf8"))
    predictor = SecureSightPredictor()
    if predictor.load()["status"] != "OK": raise RuntimeError("Required model missing")
    output = []
    for case in corpus["known_model_failures"]:
        result = predictor.predict(extract_advanced_url_features(case["url"]), include_explanations=False)
        output.append({"id": case["id"], "expected": case["expected_lexical_class"],
                       "actual": result.get("prediction"), "ml_probability": result.get("probability"),
                       "pass": result.get("prediction") == case["expected_lexical_class"],
                       "owner": case["owner"], "issue": case["issue"], "review_by": case["review_by"],
                       "scope": case["scope"]})
    report = root / "reports/phase14_20261009/known_regressions.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"cases": output, "failures": sum(not c["pass"] for c in output),
                       "training_or_threshold_change": False,
                       "historical_redirect_case": {"status": "UNAVAILABLE", "issue": "LOCAL-ML-001", "owner": "model-maintainer", "review_by": "2026-11-09", "reason": "Phase 9 retained redirected path is redacted; passing the root URL does not resolve the historical full-pipeline false positive"}}, indent=2), encoding="utf8")
    print(json.dumps({"known_failures": sum(not c["pass"] for c in output)}))
    if any(not case["pass"] for case in output):
        raise SystemExit(1)


if __name__ == "__main__": main()
