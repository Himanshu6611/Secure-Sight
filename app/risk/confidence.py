"""Provisional evidence-quality index, never a calibrated correctness probability."""
from .normalization import number

def confidence(signals, coverage, flags, config):
    selected=[s for s in signals if s.selected]
    values={s.signal_id:s.normalized_value for s in selected}
    policy=config["verdict"]
    ml=flags["ml_probability"]
    strong_ml=ml is not None and flags["model_calibrated"] and ml>=policy["high_ml_probability"]
    low_ml=ml is not None and flags["model_calibrated"] and ml<=policy["low_ml_probability"]
    malicious=flags.get("reputation_malicious",False)
    safe=flags.get("reputation_safe",False)
    harvesting=(values.get("html.external_credentials",0)>0 and values.get("brand.mismatch",0)>0)
    contradictions=[]
    if strong_ml and safe:
        contradictions.append({"code":"ML_REPUTATION_CONFLICT","reason":"URL model indicates phishing while a reliable provider reports safe."})
    if low_ml and (malicious or harvesting):
        contradictions.append({"code":"ML_OBSERVED_EVIDENCE_CONFLICT","reason":"Low URL-only probability conflicts with malicious reputation or corroborated webpage findings."})
    if safe and harvesting:
        contradictions.append({"code":"REPUTATION_WEB_CONFLICT","reason":"Provider safety report conflicts with corroborated credential harvesting evidence."})
    # URL heuristics and URL model are correlated; count both as one source.
    sources=set()
    if strong_ml or any(s.category=="URL" and s.normalized_value>=policy["alert_min_normalized"] for s in selected):
        sources.add("URL_MODEL")
    if malicious:
        sources.add("REPUTATION")
    if harvesting:
        sources.add("STATIC_WEB")
    # Agreement is based on independent sources, not the number of duplicate signals.
    agreement_value=1. if len(sources)>=2 and not contradictions else .5 if not contradictions and flags["essential_complete"] else 0.
    quality=sum(s.confidence for s in selected)/len(selected) if selected else 0.
    certainty=2*abs(ml-.5) if ml is not None and flags["model_calibrated"] else 0.
    weights=config["confidence"]
    raw=100*(weights["coverage"]*coverage/100 + weights["quality"]*quality +
        weights["agreement"]*agreement_value+weights["model"]*certainty)
    penalty=weights["contradiction_penalty"] if contradictions else 0.
    # Confidence cannot exceed evidence coverage. This is an explicit policy cap.
    final=min(coverage,max(0.,raw-penalty))
    number(final,0,100,"CONFIDENCE_CALCULATION_ERROR")
    return final,contradictions,sources,{
        "kind":"provisional evidence-quality index; not calibrated probability",
        "coverage_component":coverage*weights["coverage"],"quality_component":100*quality*weights["quality"],
        "agreement_component":100*agreement_value*weights["agreement"],"model_component":100*certainty*weights["model"],
        "contradiction_penalty":penalty,"coverage_cap":coverage,"uncapped_total":raw-penalty,
    }
