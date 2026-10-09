"""Phase 9 evidence adapter. No additional score or independent risk source.

Reuse the existing BRAND group, replacing the legacy title-only mismatch.
History/similarity/email observations remain unscored until policy validation.
"""
from app.risk.schemas import RiskError
from app.brand.analyzer import EVIDENCE_REASONS
from app.brand.config import load_registry


def brand_observation(context):
    result = context.get("brand_intelligence")
    if result is None:
        return None
    if not isinstance(result, dict) or result.get("feature_version") != "9.0.0" or result.get("status") not in {"PARTIAL", "ANALYZED", "UNAVAILABLE"}:
        raise RiskError("RISK_INPUT_INVALID")
    features = result.get("features")
    if result.get("primary_brand") is not None and result["primary_brand"] not in {b["id"] for b in load_registry()["brands"]}:
        raise RiskError("RISK_INPUT_INVALID")
    if result.get("domain_match") not in {"EXACT_MATCH", "OFFICIAL_SUBDOMAIN", "KNOWN_OFFICIAL_DOMAIN", "POSSIBLE_MATCH", "LOOKALIKE", "MISMATCH", "UNKNOWN"}:
        raise RiskError("RISK_INPUT_INVALID")
    if not isinstance(features, dict):
        raise RiskError("RISK_INPUT_INVALID")
    if result["status"] == "UNAVAILABLE":
        if features.get("corroborated_brand_mismatch") is not None:
            raise RiskError("RISK_INPUT_INVALID")
        return ({"brand_domain_mismatch":None}, "UNAVAILABLE", "phase_9")
    names = {"corroborated_brand_mismatch", "credential_page", "multi_source_claim", "strong_lookalike",
             "external_nonofficial_credentials", "known_official_match", "official_auth_destination"}
    if set(features) != names or any(type(v) is not int or v not in (0, 1) for v in features.values()):
        raise RiskError("RISK_INPUT_INVALID")
    expected = int(not features["known_official_match"] and features["credential_page"] and features["multi_source_claim"] and
        (features["external_nonofficial_credentials"] or (features["strong_lookalike"] and not features["official_auth_destination"])))
    if features["corroborated_brand_mismatch"] != expected:
        raise RiskError("RISK_INPUT_INVALID")
    actual_password = bool(context["web_intelligence"].get("html_features", {}).get("password_input_count"))
    if bool(features["credential_page"]) != actual_password:
        raise RiskError("RISK_INPUT_INVALID")
    # Unknown brands have no mismatch measurement, not an observed negative.
    value = features["corroborated_brand_mismatch"] if result.get("primary_brand") else None
    return ({"brand_domain_mismatch":value}, "AVAILABLE" if value is not None else "UNAVAILABLE", "phase_9")


def explanation_observations(result):
    if result is None:
        return []
    observations = result.get("evidence", [])
    if not isinstance(observations, list) or len(observations) > 16:
        raise RiskError("RISK_INPUT_INVALID")
    verified, seen = [], set()
    for item in observations:
        if not isinstance(item, dict) or item.get("indicator") not in EVIDENCE_REASONS or item.get("source") != "phase_9":
            raise RiskError("RISK_INPUT_INVALID")
        code = item["indicator"]
        if item.get("category") != EVIDENCE_REASONS[code][0] or type(item.get("value")) is not int or not 0 < item["value"] <= 32 or type(item.get("confidence")) not in (int, float) or not 0 <= item["confidence"] <= 1:
            raise RiskError("RISK_INPUT_INVALID")
        if code not in seen:
            verified.append(dict(indicator=code, source="phase_9", category=item["category"], value=item["value"],
                confidence=item["confidence"], score_contribution=0))
            seen.add(code)
    return verified
