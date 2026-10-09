"""Offline lexical perturbation measurement; never fetches or tunes a model."""
import json
from pathlib import Path
from ml.inference import SecureSightPredictor
from utils.url_features import extract_advanced_url_features
from app.security.urls import validate_url


def main():
    predictor = SecureSightPredictor()
    if predictor.load()["status"] != "OK":
        raise RuntimeError("Required local model unavailable")
    cases = []
    for host in ("example.com", "example.org", "www.paypal.com", "www.microsoft.com", "xn--r8jz45g.jp"):
        base = "https://" + host + "/"
        variants = {"case_and_dot": "HTTPS://" + host.upper() + "./", "benign_query": base + "?message=welcome", "encoded_path": base + "welcome%20home", "fragment": base + "#welcome"}
        original = predictor.predict(extract_advanced_url_features(validate_url(base)), include_explanations=False)
        for name, url in variants.items():
            result = predictor.predict(extract_advanced_url_features(validate_url(url)), include_explanations=False)
            cases.append({"host": host, "variation": name, "base_probability": original["probability"], "probability": result["probability"], "absolute_delta": abs(result["probability"] - original["probability"]), "label_changed": result["prediction"] != original["prediction"], "canonical_url_equal": validate_url(url) == validate_url(base)})
    report = {"scope": "20 deterministic offline lexical variations, descriptive stability only; no labeled contemporary website ground truth or attacks on these hosts", "model_version": "5.1.1", "threshold_changed": False, "model_fit": False, "cases": cases, "label_changes": sum(c["label_changed"] for c in cases), "max_absolute_probability_delta": max(c["absolute_delta"] for c in cases), "image_robustness": "UNAVAILABLE: no validated genuine/manipulated-media ground truth or active deepfake model"}
    path = Path(__file__).resolve().parents[1] / "reports/phase15_20261009/ml_robustness.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf8")
    print(json.dumps({k: report[k] for k in ("label_changes", "max_absolute_probability_delta")}))


if __name__ == "__main__":
    main()
