"""Documented bounded normalizations; invalid data is not clamped away."""
import math
from .schemas import RiskError

def number(value, minimum=None, maximum=None, code="INVALID_SIGNAL"):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RiskError(code)
    if not math.isfinite(value) or (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        raise RiskError(code)
    return float(value)

def boolean(value):
    if value not in (True, False, 0, 1) or not isinstance(value, (bool,int,float)):
        raise RiskError("INVALID_SIGNAL")
    return int(value)

def normalize(value, definition):
    if value is None:
        return None
    formula = definition["formula"]
    maximum = definition["maximum"]
    if formula in {"boolean","inverse_boolean"}:
        result = boolean(value)
        if formula == "inverse_boolean":
            result = 1-result
    elif formula == "probability":
        result = number(value, 0, 1)
    elif formula in {"ramp","inverse_ramp"}:
        raw = number(value, 0)
        result = min(1., max(0., (raw-definition["low"])/(definition["high"]-definition["low"])))
        if formula == "inverse_ramp":
            result = 1-result
    elif formula == "status":
        if value not in {"SAFE","SUSPICIOUS","MALICIOUS"}:
            raise RiskError("INVALID_SIGNAL")
        result = definition["status_values"][value]
    else:
        raise RiskError("SCORING_CONFIGURATION_ERROR")
    return result * maximum
