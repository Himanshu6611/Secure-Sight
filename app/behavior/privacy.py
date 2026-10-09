"""Public evidence hides all path/query/fragment values, including unknown token keys."""
from urllib.parse import urlsplit, urlunsplit, urljoin
from app.security.urls import validate_url, InvalidURL


def redact_url(value):
    try:
        parsed = urlsplit(validate_url(value))
        # Paths can carry reset/session tokens too; query names can contain personal data.
        return urlunsplit((parsed.scheme, parsed.netloc, "/[path-redacted]" if parsed.path not in {"", "/"} else parsed.path,
                           "[query-redacted]" if parsed.query else "", ""))
    except (InvalidURL, ValueError, TypeError):
        return "[restricted-or-invalid-destination]"


def normalize_destination(value):
    parsed = urlsplit(validate_url(value))
    host = parsed.hostname
    if ":" in host:
        host = "[" + host + "]"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    authority = host if port == (443 if parsed.scheme == "https" else 80) else host + ":" + str(port)
    # Fragments never reach HTTP servers and cannot hide an HTTP loop.
    return urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))


def sanitize_public_web(result, target):
    """Remove internal routing and redact legacy URL fields after analysis is complete."""
    result.pop("_brand_inventory", None)
    result.pop("_analysis_target", None)
    result["title"] = "[remote-title-omitted]" if result.get("title") else ""
    for key in ("canonical_url", "favicon_url"):
        if result.get(key):
            result[key] = redact_url(result[key])
    for form in result.get("forms", []):
        for key in ("action", "resolved_action"):
            if form.get(key):
                form[key] = redact_url(urljoin(target, form[key]))
    for resource in result.get("resources", []):
        if resource.get("url"):
            resource["url"] = redact_url(resource["url"])
    summary = result.get("fetch_summary", {})
    if summary.get("final_url") and "[" not in summary["final_url"]:
        summary["final_url"] = redact_url(summary["final_url"])
    return result
