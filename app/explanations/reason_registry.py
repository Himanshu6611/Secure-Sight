"""Load a bounded trusted JSON registry; page content never defines policy."""
import copy
import hashlib
import json
from string import Formatter
from pathlib import Path
from ml.features import URL_FEATURE_ORDER
from app.risk.config import load_config

CATEGORIES = frozenset("URL DOMAIN DNS TLS REPUTATION HTML DOM FORM SCRIPT CONTENT NLP BRAND REDIRECT ML BEHAVIORAL HISTORICAL SYSTEM".split())
SEVERITIES = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
EVIDENCE_TYPES = frozenset("OBSERVED INFERRED MODEL_DERIVED EXTERNAL MISSING CONTRADICTORY".split())


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate explanation configuration key")
        result[key] = value
    return result


def validate_registry(value):
    value = copy.deepcopy(value)
    if set(value) != {"version", "limits", "signals", "features", "messages", "contradictions", "floors"}:
        raise ValueError("Invalid explanation registry fields")
    if value["version"] != "7.2.0":
        raise ValueError("Unsupported explanation version")
    limits = value["limits"]
    bounds = {"top_reasons": (1, 7), "max_reasons": (7, 64), "max_description": (200, 600), "max_total_bytes": (4096, 65536)}
    if set(limits) != set(bounds):
        raise ValueError("Invalid explanation limits")
    for key, (low, high) in bounds.items():
        if type(limits[key]) is not int or not low <= limits[key] <= high:
            raise ValueError("Invalid explanation limit")
    if set(value["signals"]) != {s["id"] for s in load_config()["signals"]} or set(value["features"]) != set(URL_FEATURE_ORDER):
        raise ValueError("Incomplete explanation mapping")
    for entry in value["signals"].values():
        if not isinstance(entry, dict):
            raise ValueError("Invalid reason entry")
        if entry.get("category") not in CATEGORIES or not {"category", "title", "description"} <= set(entry) or set(entry)-{"category", "title", "description", "negative"}:
            raise ValueError("Invalid reason entry")
        if "negative" in entry and set(entry["negative"]) != {"title", "description"}:
            raise ValueError("Invalid negative reason entry")
        if any(not isinstance(entry[key], str) for key in ("category", "title", "description")):
            raise ValueError("Invalid reason text")
        if "negative" in entry and any(not isinstance(text, str) for text in entry["negative"].values()):
            raise ValueError("Invalid negative reason text")
    if any(not isinstance(text, str) for text in value["features"].values()) or any(not isinstance(text, str) for text in value["contradictions"].values()):
        raise ValueError("Invalid translation text")
    def check_text(item):
        if isinstance(item, dict):
            for nested in item.values():
                check_text(nested)
        elif isinstance(item, list):
            for nested in item:
                check_text(nested)
        elif isinstance(item, str):
            if not item or len(item) > limits["max_description"] or any(c in item for c in "<>\x00"):
                raise ValueError("Unsafe explanation template")
        else:
            raise ValueError("Explanation wording must be text")
    check_text({key: value[key] for key in ("signals", "features", "messages", "contradictions", "floors")})
    expected = {"summary", "reason_suffix", "missing_title", "missing_description", "not_applicable", "password_title", "password_description", "ml_feature_description", "ml_unavailable", "invalid", "size_limit", "consistency", "model_limit", "confidence_limit", "dynamic", "external", "floor", "behavior_adjustment"}
    if set(value["messages"]) != expected or set(value["messages"]["summary"]) != {"PHISHING", "SUSPICIOUS", "LEGITIMATE", "UNKNOWN", "ANALYSIS_FAILED"}:
        raise ValueError("Incomplete explanation messages")
    if not isinstance(value["messages"]["summary"], dict) or any(not isinstance(text, str) for text in value["messages"]["summary"].values()):
        raise ValueError("Invalid summary text")
    if any(not isinstance(text, str) for key, text in value["messages"].items() if key != "summary"):
        raise ValueError("Invalid message text")
    if set(value["contradictions"]) != {"ML_REPUTATION_CONFLICT", "ML_OBSERVED_EVIDENCE_CONFLICT", "REPUTATION_WEB_CONFLICT"}:
        raise ValueError("Invalid contradiction mapping")
    if value["floors"] != ["CORROBORATED_CREDENTIAL_HARVESTING", "MODEL_AND_CORROBORATED_HARVESTING", "CONFIRMED_REPUTATION_AND_HARVESTING"]:
        raise ValueError("Invalid adjustment mapping")
    placeholders = {"reason_suffix": {"titles"}, "missing_description": {"name"}, "password_description": {"count"}, "ml_feature_description": {"impact"}}
    for key, wording in value["messages"].items():
        if isinstance(wording, str):
            parsed = list(Formatter().parse(wording))
            if any(spec or conversion for _, _, spec, conversion in parsed):
                raise ValueError("Unsafe explanation format")
            fields = {field for _, field, _, _ in parsed if field is not None}
            if fields != placeholders.get(key, set()):
                raise ValueError("Unsupported explanation placeholder")
    return value


def load_registry():
    path = Path(__file__).resolve().parents[2] / "config" / "explanations.json"
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError("Explanation registry exceeds limit")
    return validate_registry(json.loads(raw, object_pairs_hook=_unique))


def registry_digest(registry):
    return hashlib.sha256(json.dumps(registry, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
