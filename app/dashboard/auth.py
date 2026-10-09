"""Server-enforced tenant roles, expiring sessions and CSRF."""
import hmac
import secrets
import time
from functools import wraps
from flask import current_app, g, request, session
from werkzeug.exceptions import Unauthorized, Forbidden


def csrf():
    if "dashboard_csrf" not in session:
        session["dashboard_csrf"] = secrets.token_urlsafe(32)
    return session["dashboard_csrf"]


def check_csrf():
    value = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if not isinstance(value, str) or not value.isascii() or len(value) > 128 or not hmac.compare_digest(session.get("dashboard_csrf", "NO_TOKEN"), value):
        raise Forbidden()


def load_principal():
    store = current_app.extensions.get("dashboard_store")
    g.dashboard_principal = None
    g.dashboard_bearer = False
    if store is None:
        return
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        if len(header) <= 135 and header.isascii():
            g.dashboard_principal = store.bearer(header[7:])
        g.dashboard_bearer = bool(g.dashboard_principal)
    if not header and time.time() < session.get("dashboard_expires", 0):
        g.dashboard_principal = store.user(session.get("dashboard_user", ""))
    if g.dashboard_principal and request.method in {"POST", "PATCH", "DELETE", "PUT"} and not g.dashboard_bearer:
        check_csrf()
    if g.dashboard_principal and request.endpoint in {"main.index", "api.scan", "api.legacy_scan", "api.email_analyze_endpoint", "api.analyze_media_endpoint"} and request.method == "POST" and g.dashboard_principal["role"] == "VIEWER":
        # A viewer may inspect history but cannot create private investigation records.
        raise Forbidden()


def require(*roles):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            principal = getattr(g, "dashboard_principal", None)
            if not principal:
                raise Unauthorized()
            if roles and principal["role"] not in roles:
                raise Forbidden()
            return fn(*args, **kwargs)
        return wrapped
    return decorate
