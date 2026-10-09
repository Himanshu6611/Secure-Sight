"""Select one strongest observation per group; renormalize observed weights."""
from dataclasses import replace
from .schemas import RiskError

def aggregate(signals, config):
    category_scores={}; details={}; selected_ids=set(); coverage=0.
    for category, category_weight in config["categories"].items():
        candidates=[s for s in signals if s.category.lower()==category]
        expected=observed=weighted=0.
        groups={}
        for group, group_weight in config["groups"][category].items():
            records=[s for s in candidates if s.group==group]
            if all(s.state=="NOT_APPLICABLE" for s in records):
                continue
            expected+=group_weight
            available=[s for s in records if s.state=="AVAILABLE"]
            if not available:
                groups[group]={"state":"UNAVAILABLE","signal_id":None,"score":None,"weight":group_weight}
                continue
            chosen=sorted(available,key=lambda s:(-s.normalized_value,-s.confidence,s.signal_id))[0]
            selected_ids.add(chosen.signal_id)
            weighted+=chosen.normalized_value*group_weight
            observed+=group_weight
            groups[group]={"state":"AVAILABLE","signal_id":chosen.signal_id,"score":chosen.normalized_value*100,"weight":group_weight}
        category_scores[category]=weighted/observed*100 if observed else None
        ratio=observed/expected if expected else 1.
        coverage+=category_weight*ratio
        details[category]={"configured_weight":category_weight,"observed_group_fraction":ratio,"groups":groups}
    available_weight=sum(config["categories"][category] for category,score in category_scores.items() if score is not None)
    risk=sum(score*config["categories"][category]/available_weight for category,score in category_scores.items() if score is not None) if available_weight else None
    contributions={}
    for category,detail in details.items():
        observed=sum(v["weight"] for v in detail["groups"].values() if v["state"]=="AVAILABLE")
        for group in detail["groups"].values():
            if group["signal_id"]:
                contributions[group["signal_id"]]=group["score"]*group["weight"]/observed*config["categories"][category]/available_weight
    audit_signals=[replace(s,selected=s.signal_id in selected_ids,contribution=contributions.get(s.signal_id,0.)) for s in signals]
    if risk is not None and not 0<=risk<=100+1e-8:
        raise RiskError("INVALID_SCORE")
    return risk,category_scores,coverage*100,details,audit_signals
