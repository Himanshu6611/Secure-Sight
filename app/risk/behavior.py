"""Behavioral scoring belongs only to Phase 6; correlated effects use a maximum."""
import copy
from app.behavior.evidence import validate_behavior, indicator


def incorporate_behavior(context, flags, config):
    behavior = context.get("behavior_intelligence")
    if behavior is None:
        return [], 0., None
    validate_behavior(behavior)
    evidence = list({item["indicator"]: copy.deepcopy(item) for item in behavior["indicators"]}.values())
    if behavior["features"]["redirect_count"] and behavior["status"] == "ANALYZED" and (
        flags["reputation_malicious"] or (flags["model_calibrated"] and flags["ml_probability"] >= config["verdict"]["high_ml_probability"])):
        evidence.append(indicator("BEHAVIOR_SUSPICIOUS_FINAL_DESTINATION", 1, .9, "INFERRED"))
    policy = config["behavior"]
    points = max((policy["indicator_points"].get(r["indicator"], 0) for r in evidence), default=0.)
    points = min(points, policy["maximum_adjustment"])
    selected = next((r["indicator"] for r in evidence if points and policy["indicator_points"].get(r["indicator"], 0) == points), None)
    for item in evidence:
        item["score_contribution"] = points if item["indicator"] == selected else 0.
    if behavior["status"] != "ANALYZED" and policy["failure_blocks_definitive"]:
        flags["essential_complete"] = False
        flags["observed_web"] = False
    # Static targets are not visited; incomplete navigation remains explicit.
    if behavior["features"]["meta_refresh_detected"] or behavior["features"]["js_redirect_detected"]:
        flags["essential_complete"] = False
        flags["observed_web"] = False
    return evidence, points, behavior["status"]
