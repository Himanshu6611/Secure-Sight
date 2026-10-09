"""Allowlist scalar evidence. Raw URLs, text, identifiers and secrets are omitted."""
import math
from .reason_registry import CATEGORIES, SEVERITIES, EVIDENCE_TYPES


def number(value, low=0, high=1e12):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError("Invalid numeric evidence")
    return value


def validate_reason(reason, max_description):
    if reason["category"] not in CATEGORIES or reason["severity"] not in SEVERITIES or reason["evidence_type"] not in EVIDENCE_TYPES:
        raise ValueError("Invalid explanation classification")
    for key in ("reason_id", "signal_id", "source", "title", "description"):
        text = reason[key]
        if not isinstance(text, str) or not text or len(text) > max_description or any(c in text for c in "<>\x00"):
            raise ValueError("Unsafe explanation text")
    number(reason["confidence"], 0, 1)
    if "score_contribution" in reason:
        number(reason["score_contribution"], 0, 100)
    for value in reason["evidence"].values():
        if type(value) is bool:
            continue
        elif isinstance(value, str):
            if value not in {"SAFE", "SUSPICIOUS", "MALICIOUS", "AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "ERROR", "PARTIAL", "SKIPPED"}:
                raise ValueError("Unsupported text evidence")
        else:
            number(value, -1e12, 1e12)
    return reason
