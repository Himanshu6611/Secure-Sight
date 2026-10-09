"""Bounded strict JSON for requests and untrusted provider responses."""
import json
import math
from typing import TypedDict, NotRequired
from flask.json.provider import DefaultJSONProvider


class ScanRequest(TypedDict):
    url: str
    email_context: NotRequired[dict[str, str]]


class EmailRequest(TypedDict, total=False):
    raw_email: str
    messages: list[str]


class ErrorDetail(TypedDict):
    code: str
    message: str


class ErrorResponse(TypedDict):
    error: ErrorDetail
    request_id: str | None


def strict_loads(raw, *, max_depth=16, max_nodes=16384, max_items=1024, **kwargs):
    # Inspect structural depth before Python's recursive parser allocates objects.
    text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise ValueError("JSON nesting limit")
        elif char in "]}":
            depth -= 1

    def object_pairs(pairs):
        value = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("Duplicate JSON field")
            value[key] = child
        return value

    def constant(value):
        raise ValueError("Non-finite JSON value")

    kwargs.update(object_pairs_hook=object_pairs, parse_constant=constant)
    value = json.loads(text, **kwargs)
    pending, count = [value], 0
    while pending:
        item = pending.pop()
        count += 1
        if count > max_nodes:
            raise ValueError("JSON node limit")
        if isinstance(item, (dict, list)):
            if len(item) > max_items:
                raise ValueError("JSON collection limit")
            pending.extend(item.values() if isinstance(item, dict) else item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("Non-finite JSON number")
    return value


class StrictJSONProvider(DefaultJSONProvider):
    def loads(self, value, **kwargs):
        return strict_loads(value, **kwargs)
