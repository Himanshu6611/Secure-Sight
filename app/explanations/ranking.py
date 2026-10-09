"""Rank existing contributions and prefer distinct correlation groups."""
from .reason_registry import SEVERITIES


def rank_reasons(reasons, limit):
    ranked = sorted(reasons, key=lambda r: (
        -r.get("score_contribution", 0), -SEVERITIES[r["severity"]],
        -r["confidence"], -r["source_reliability"], r["reason_id"]))
    grouped = {}
    for reason in ranked:
        grouped.setdefault(reason["independence_group"], reason)
    return list(grouped.values())[:limit]
