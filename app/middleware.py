"""Common request policy, limits, correlation and safe responses."""
import secrets
import time
import uuid
from threading import BoundedSemaphore
from flask import g, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException, Forbidden, RequestEntityTooLarge, ServiceUnavailable
from .security.urls import InvalidURL
from .security.json_policy import ErrorResponse


def install(app):
    app.extensions["scan_slots"] = BoundedSemaphore(app.config["MAX_CONCURRENT_SCANS"])

    @app.before_request
    def request_policy():
        g.request_id = uuid.uuid4().hex
        g.started = time.monotonic()
        g.csp_nonce = secrets.token_urlsafe(24)
        g.scan_slot = False
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("Origin")
            # Host has already passed Flask's TRUSTED_HOSTS validation.
            allowed = {request.host_url.rstrip("/"), app.config["SITE_URL"], *app.config["ALLOWED_ORIGINS"]}
            if origin and origin not in allowed:
                raise Forbidden()
            if request.headers.get("Sec-Fetch-Site") == "cross-site" and not origin:
                raise Forbidden()
            if request.path.startswith("/api/") and not (request.path == "/api/v1/media/analyze" or request.path == "/api/v1/email/analyze" and request.mimetype == "multipart/form-data"):
                request.max_content_length = app.config["MAX_JSON_BYTES"]
            if request.content_length and request.content_length > request.max_content_length:
                raise RequestEntityTooLarge()

    limiter = Limiter(key_func=get_remote_address, app=app,
                      application_limits=[app.config["SCAN_RATE_LIMIT"]],
                      application_limits_per_method=False,
                      application_limits_exempt_when=lambda: request.method != "POST",
                      strategy="fixed-window", swallow_errors=False,
                      storage_options={"socket_connect_timeout": 2, "socket_timeout": 2}
                      if app.config["RATELIMIT_STORAGE_URI"].startswith(("redis://", "rediss://")) else {})
    app.extensions["scan_limiter"] = limiter
    if app.config["APP_ENV"] == "production" and not limiter.storage.check():
        raise ValueError("Rate-limit storage is unavailable.")

    @app.teardown_request
    def release_capacity(error):
        if getattr(g, "scan_slot", False):
            app.extensions["scan_slots"].release()
            g.scan_slot = False

    @app.errorhandler(Exception)
    def handle_error(error):
        if isinstance(error, HTTPException):
            status = error.code or 500
            code = "INVALID_URL" if isinstance(error, InvalidURL) else {
                400: "INVALID_INPUT", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 413: "RESOURCE_LIMIT",
                429: "RATE_LIMITED", 503: "PROVIDER_UNAVAILABLE"}.get(status, error.name.upper().replace(" ", "_"))
            messages = {400: "Invalid request.", 401: "Authentication required.", 403: "This request is not allowed.",
                        404: "Not found.", 405: "Method not allowed.", 413: "Request is too large.",
                        415: "Expected application/json.", 429: "Too many requests. Please retry later.",
                        503: "Service temporarily unavailable. Please retry later."}
            message = InvalidURL.description if isinstance(error, InvalidURL) else messages.get(status, "Request failed.")
            app.logger.warning("request_rejected", extra={"status": status, "error_type": type(error).__name__, "error_code": code})
        else:
            status, code, message = 500, "INTERNAL_ERROR", "Unable to process the request."
            app.logger.exception("request_failed")
        if request.path.startswith("/api/"):
            body: ErrorResponse = {"error": {"code": code, "message": message}, "request_id": getattr(g, "request_id", None)}
            response = jsonify(body)
        else:
            response = app.make_response(render_template("error.html", message=message, request_id=getattr(g, "request_id", None)))
        response.status_code = status
        if isinstance(error, HTTPException):
            for key, value in error.get_headers():
                if key.lower() in {"allow", "retry-after"}:
                    response.headers[key] = value
        if status in {429, 503}:
            response.headers.setdefault("Retry-After", "60" if status == 429 else "5")
        return response

    @app.after_request
    def finish(response):
        nonce = getattr(g, "csp_nonce", "")
        response.headers.update({
            "X-Request-ID": getattr(g, "request_id", ""),
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": (
                "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; "
                f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
                "img-src 'self' data:; connect-src 'self';"
            ),
        })
        if app.config["APP_ENV"] == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.method == "POST" or request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if request.path.startswith("/api/"):
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
            response.vary.add("Origin")
            if request.headers.get("Origin") in app.config["ALLOWED_ORIGINS"]:
                response.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type"
                response.headers["Access-Control-Expose-Headers"] = "X-Request-ID, Retry-After"
            # Include correlation on route-specific errors; success uses the header.
            if response.status_code >= 400 and response.is_json and not response.direct_passthrough:
                data = response.get_json(silent=True)
                if isinstance(data, dict):
                    data.setdefault("request_id", getattr(g, "request_id", None))
                    if isinstance(data.get("error"), dict):
                        g.response_error_code = data["error"].get("code")
                    # Preserve immutable exported reports and their attachment bytes.
                    if request.endpoint != "dashboard.export" and "error" in data:
                        response.set_data(app.json.dumps(data) + "\n")
        if request.endpoint == "dashboard.export":
            response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
        app.logger.info("request_completed", extra={"endpoint": request.endpoint or "unmatched", "status": response.status_code,
                        "error_code": getattr(g, "response_error_code", None),
                        "duration_ms": round((time.monotonic() - getattr(g, "started", time.monotonic())) * 1000, 2)})
        return response


def install_scan_capacity(app):
    """Register after identity/CSRF hooks: private writes cannot consume scan slots."""
    detectors = {"main.index", "api.scan", "api.legacy_scan", "api.email_analyze_endpoint",
                 "api.analyze_media_endpoint", "api.extract_url_features_endpoint", "api.ml_predict_endpoint",
                 "api.domain_intelligence_endpoint", "api.analyze_webpage_endpoint"}
    limiter = app.extensions["scan_limiter"]
    for endpoint in detectors:
        if endpoint in app.view_functions:
            # Decorators run after principal loading, unlike Limiter's early IP hook.
            app.view_functions[endpoint] = limiter.limit(
                lambda: app.config["ACTOR_SCAN_RATE_LIMIT"],
                key_func=lambda: g.dashboard_principal["id"],
                exempt_when=lambda: not getattr(g, "dashboard_principal", None),
                methods=["POST"])(app.view_functions[endpoint])

    @app.before_request
    def scan_capacity():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.is_json:
            # Cached parsing protects every JSON API before detector/model/provider work.
            request.get_json()
        if len(request.query_string) > 4096 or len(request.args) > 32:
            from werkzeug.exceptions import BadRequest
            raise BadRequest()
        if request.method == "POST" and request.endpoint in detectors:
            if not app.extensions["scan_slots"].acquire(blocking=False):
                raise ServiceUnavailable()
            g.scan_slot = True
            app.logger.info("scan_started", extra={"endpoint": request.endpoint})
