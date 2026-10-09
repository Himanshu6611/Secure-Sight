"""Fixed trusted bounded configuration; dynamic execution cannot be enabled."""
import copy
import json
from pathlib import Path
from app.risk.config import unique_object

PATH = Path(__file__).resolve().parents[2] / "config" / "behavior.json"


def load_config():
    raw = PATH.read_bytes()
    if len(raw) > 16384:
        raise ValueError("Behavior configuration exceeds limit")
    return validate_config(json.loads(raw, object_pairs_hook=unique_object))


def validate_config(config):
    config = copy.deepcopy(config)
    expected = {"version", "max_redirects", "request_timeout_seconds", "total_timeout_seconds", "max_response_size_bytes",
        "max_total_response_bytes", "max_static_destinations", "excessive_redirect_threshold", "domain_hopping_threshold",
        "rapid_domain_hopping_window_seconds", "dynamic_enabled", "sensitive_query_keys"}
    if set(config) != expected or config["version"] != "8.0.0" or config["dynamic_enabled"] is not False:
        raise ValueError("Unsupported behavior configuration")
    bounds = {"max_redirects": (0, 10), "max_response_size_bytes": (1, 1048576), "max_total_response_bytes": (1, 1048576),
              "max_static_destinations": (1, 32), "excessive_redirect_threshold": (1, 10), "domain_hopping_threshold": (2, 10)}
    for key, (low, high) in bounds.items():
        if type(config[key]) is not int or not low <= config[key] <= high:
            raise ValueError("Invalid behavior limit")
    from math import isfinite
    for key in ("request_timeout_seconds", "total_timeout_seconds", "rapid_domain_hopping_window_seconds"):
        value = config[key]
        if type(value) not in (int, float) or not isfinite(value) or not 0 < value <= 15:
            raise ValueError("Invalid behavior timeout")
    if not isinstance(config["sensitive_query_keys"], list) or len(config["sensitive_query_keys"]) > 64 or any(
        not isinstance(key, str) or not key.isidentifier() or len(key) > 32 for key in config["sensitive_query_keys"]):
        raise ValueError("Invalid redaction keys")
    return config
