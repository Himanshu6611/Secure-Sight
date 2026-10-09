"""Translate only actual serving-model perturbations; never generate impacts here."""
from .validation import number

METHOD = "feature_median_perturbation; model sensitivity, not causal attribution"


def translate_ml(result, assessment, registry):
    empty = {"status": "UNAVAILABLE", "scope": "LOCAL", "features": []}
    if not isinstance(result, dict) or result.get("status") != "OK" or result.get("model_validated") is not True:
        return empty
    if result.get("model_version") != assessment.get("model_version") or result.get("feature_schema_version") != assessment.get("feature_schema_version"):
        return empty
    if result.get("explanation_method") != METHOD or result.get("model_version") != "5.1.1":
        return empty
    try:
        probability = number(result["probability"], 0, 1)
        if probability != assessment.get("ml_probability") or result.get("prediction") not in {"legitimate", "phishing"}:
            return empty
        records = result.get("explanations")
        if not isinstance(records, list) or len(records) > 10:
            return empty
        features, seen = [], set()
        for record in records:
            if not isinstance(record, dict):
                continue
            name = record.get("feature")
            if not isinstance(name, str) or name not in registry["features"] or name in seen:
                continue
            try:
                value = number(record["value"])
                delta = number(record["contribution"], -1, 1)
                baseline = number(record["baseline_value"])
                perturbed = number(record["perturbed_probability"], 0, 1)
                if abs((probability-perturbed)-delta) > 2e-6:
                    continue
                impact = "positive" if delta > 0 else "negative" if delta < 0 else "neutral"
                if record.get("impact") != impact:
                    continue
            except (KeyError, ValueError, TypeError):
                continue
            seen.add(name)
            features.append({"name": name, "title": registry["features"][name], "value": value,
                "impact": delta, "magnitude": abs(delta),
                "direction": "risk_increasing" if delta > 0 else "risk_reducing" if delta < 0 else "neutral",
                "baseline_value": baseline, "perturbed_probability": perturbed,
                "description": registry["messages"]["ml_feature_description"].format(impact=f"{delta:+.6f}"),
                "source": "phase_5", "evidence_type": "MODEL_DERIVED"})
        features.sort(key=lambda r: (-r["magnitude"], r["name"]))
        if not features:
            return empty
        return {"status": "AVAILABLE", "scope": "LOCAL", "method": METHOD,
                "prediction": result["prediction"], "probability": probability,
                "model_version": result["model_version"], "features": features,
                "limitations": registry["messages"]["model_limit"]}
    except (KeyError, ValueError, TypeError):
        return empty
