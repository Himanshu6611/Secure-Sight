"""Single centralized verdict policy; missing evidence never proves safety."""
def severity(score, config):
    if score is None:
        return "UNKNOWN"
    return next(band["name"] for band in reversed(config["severity"]) if score>=band["minimum"])

def verdict(score, certainty, coverage, flags, sources, contradictions, config):
    policy=config["verdict"]
    if score is None:
        return "ANALYSIS_FAILED"
    if (score>=policy["phishing_min_risk"] and certainty>=policy["minimum_confidence_for_phishing"]
        and coverage>=policy["minimum_coverage_for_phishing"] and len(sources)>=policy["minimum_phishing_sources"]
        and not contradictions and flags["dns_safe"] and flags["observed_web"]):
        return "PHISHING"
    if not flags["essential_complete"] or not flags["dns_safe"] or flags.get("tls_unsafe"):
        return "SUSPICIOUS" if len(sources)>=2 and score>=policy["suspicious_min_risk"] else "UNKNOWN"
    if (score>=policy["suspicious_min_risk"] or sources or contradictions or flags.get("reputation_suspicious") or flags.get("unconfirmed_external_credentials")):
        return "SUSPICIOUS"
    if (score<=policy["legitimate_max_risk"] and certainty>=policy["minimum_confidence_for_legitimate"]
        and coverage>=policy["minimum_coverage_for_legitimate"] and not contradictions and not flags.get("analysis_partial", False)):
        return "LEGITIMATE"
    return "UNKNOWN"
