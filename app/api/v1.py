"""Small versioned API with a compatibility alias."""
from flask import Blueprint, jsonify, request, current_app, g
from werkzeug.exceptions import BadRequest
from app.services.scans import scan_url
from app.security.json_policy import ScanRequest, EmailRequest

bp = Blueprint("api", __name__)


@bp.post("/api/v1/email/analyze")
def email_analyze_endpoint():
    from app.email.parser import EmailError, MAX_EMAIL_BYTES
    from app.email.jobs import get_jobs
    try:
        if request.mimetype == "multipart/form-data":
            if set(request.files) != {"file"} or len(request.files.getlist("file")) != 1 or request.form:
                raise EmailError("INVALID_EMAIL")
            file = request.files["file"]
            raw = file.stream.read(MAX_EMAIL_BYTES + 1)
            suffix = (file.filename or "").rsplit(".", 1)[-1].lower()
            if suffix == "eml":
                if file.mimetype not in {"message/rfc822", "text/plain", "application/octet-stream"}:
                    raise EmailError("UNSUPPORTED_EMAIL_FORMAT", 415)
            elif suffix in {"pdf", "docx", "xml"}:
                from app.media.worker import run
                from app.media.intake import MediaError
                from email.message import EmailMessage
                try:
                    extracted = run(raw, {"mime": "--email-document"}, suffix,
                                    wall_seconds=8, output_limit=512 * 1024)
                except MediaError as exc:
                    raise EmailError(exc.code, exc.status) from None
                message = EmailMessage()
                message["Subject"] = f"Uploaded {suffix.upper()} document; original email headers unavailable"
                message["X-SecureSight-Input-Format"] = suffix
                message.set_content(extracted["text"])
                raw = message.as_bytes()
            else:
                raise EmailError("UNSUPPORTED_EMAIL_FORMAT", 415)
        else:
            data: EmailRequest = request.get_json()
            if isinstance(data, dict) and set(data) == {"messages"} and isinstance(data["messages"], list):
                if not 1 <= len(data["messages"]) <= 3 or any(not isinstance(value, str) or not value.strip() for value in data["messages"]):
                    raise EmailError("INVALID_EMAIL_BATCH")
                raw = [value.encode("utf-8") for value in data["messages"]]
            elif isinstance(data, dict) and set(data) == {"raw_email"} and isinstance(data["raw_email"], str):
                raw = data["raw_email"].encode("utf-8")
            else:
                raise EmailError("INVALID_EMAIL")
        if isinstance(raw, bytes) and (not raw.strip() or len(raw) > MAX_EMAIL_BYTES):
            raise EmailError("EMAIL_RESOURCE_LIMIT" if raw else "INVALID_EMAIL", 413 if raw else 400)
        response = jsonify(get_jobs().submit(current_app._get_current_object(), raw))
        response.status_code = 202
        response.headers["Cache-Control"] = "no-store"
        return response
    except EmailError as exc:
        return jsonify(analysis_status="FAILED", risk={"verdict": "UNKNOWN", "risk_score": None}, error={"code": exc.code}), exc.status


@bp.get("/api/v1/email/jobs/<job_id>")
def email_job_endpoint(job_id):
    from app.email.jobs import get_jobs
    authorization = request.headers.get("Authorization", "")
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    try:
        result = get_jobs().read(job_id, token) if len(token) <= 128 else None
    except Exception:
        return jsonify(error={"code": "EMAIL_JOB_STORE_UNAVAILABLE"}, analysis_status="FAILED", risk={"verdict": "UNKNOWN"}), 503
    response = jsonify(result) if result else jsonify(error={"code": "EMAIL_JOB_NOT_FOUND"})
    response.status_code = 200 if result else 404
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/api/v1/media/analyze")
def analyze_media_endpoint():
    from app.media.service import analyze
    from app.media.intake import MediaError
    from app.brand.analyzer import validate_email_context
    if request.mimetype != "multipart/form-data":
        return jsonify(error={"code": "INVALID_MEDIA"}, analysis_status="FAILED"), 415
    try:
        if set(request.files) != {"file"} or len(request.files.getlist("file")) != 1 or set(request.form) - {"language", "email_context", "source_url"}:
            raise MediaError("INVALID_MEDIA")
        if any(len(request.form.getlist(key)) != 1 for key in request.form):
            raise MediaError("INVALID_MEDIA")
        context = request.form.get("email_context")
        if context:
            if len(context) > 4096:
                raise MediaError("RESOURCE_LIMIT", 413)
            from app.security.json_policy import strict_loads
            context = validate_email_context(strict_loads(context))
        result = analyze(request.files["file"], request.form.get("language", "eng"), context, request.form.get("source_url"))
        from app.dashboard.service import capture
        identity = capture(result, "MEDIA")
        if identity:
            result["investigation_id"] = identity
        return jsonify(result)
    except MediaError as exc:
        return jsonify(error={"code": exc.code, "message": "Media analysis could not be completed."},
                       analysis_status="FAILED", verdict="UNKNOWN", risk_score=None), exc.status
    except (ValueError, TypeError):
        return jsonify(error={"code": "INVALID_MEDIA"}, analysis_status="FAILED", verdict="UNKNOWN"), 400


@bp.post("/api/v1/media/investigate")
def investigate_media_endpoint():
    """Evidence-report contract; external providers remain opt-in and unavailable by default."""
    from app.media.service import analyze
    from app.media.intake import MediaError
    if request.mimetype != "multipart/form-data":
        return jsonify(error={"code": "INVALID_MEDIA"}, analysis_status="FAILED"), 415
    try:
        if set(request.files) != {"image"} or len(request.files.getlist("image")) != 1:
            raise MediaError("INVALID_MEDIA")
        allowed_fields = {"checks", "reverse_search", "content_safety", "language"}
        if set(request.form) - allowed_fields or any(len(request.form.getlist(key)) != 1 for key in request.form):
            raise MediaError("INVALID_MEDIA")
        allowed_checks = {"c2pa", "metadata", "ai_detector", "forensics", "watermark",
                          "reverse_image_search", "content_safety"}
        raw_checks = request.form.get("checks", "")
        checks = [item.strip() for item in raw_checks.split(",") if item.strip()] if raw_checks else None
        if checks is not None and (not checks or len(checks) != len(set(checks)) or set(checks) - allowed_checks):
            raise MediaError("INVALID_OPTIONS")
        bool_fields = {}
        for name in ("reverse_search", "content_safety"):
            value = request.form.get(name, "false").lower()
            if value not in {"true", "false"}:
                raise MediaError("INVALID_OPTIONS")
            bool_fields[name] = value == "true"
        result = analyze(request.files["image"], request.form.get("language", "eng"),
                         reverse_search=bool_fields["reverse_search"],
                         content_safety=bool_fields["content_safety"], requested_checks=checks)
        from app.dashboard.service import capture
        identity = capture(result, "MEDIA")
        if identity:
            result["investigation_id"] = identity
        response = jsonify(result)
        response.headers["Cache-Control"] = "no-store"
        return response
    except MediaError as exc:
        return jsonify(error={"code": exc.code, "message": "Image investigation could not be completed."},
                       analysis_status="FAILED", verdict="UNKNOWN", risk_score=None), exc.status
    except (ValueError, TypeError):
        return jsonify(error={"code": "INVALID_MEDIA"}, analysis_status="FAILED", verdict="UNKNOWN"), 400


def _scan():
    data: ScanRequest = request.get_json()
    if not isinstance(data, dict) or set(data) - {"url", "email_context"}:
        raise BadRequest()
    if "url" not in data or data["url"] == "":
        return jsonify(error={"code": "MISSING_URL", "message": "No URL provided."}, request_id=g.request_id), 400
    if "email_context" in data:
        from app.brand.analyzer import validate_email_context
        try:
            data["email_context"] = validate_email_context(data["email_context"])
        except ValueError:
            raise BadRequest() from None
    result = scan_url(data["url"], email_context=data["email_context"]) if "email_context" in data else scan_url(data["url"])
    from app.dashboard.service import capture
    identity = capture(result, "URL")
    if identity:
        result["investigation_id"] = identity
    return jsonify(result)


@bp.post("/api/v1/scan")
def scan():
    return _scan()


@bp.post("/api/v1/features/url")
def extract_url_features_endpoint():
    data = request.get_json()
    if not isinstance(data, dict) or set(data) - {"url"}:
        raise BadRequest()
    if "url" not in data or not data["url"]:
        return jsonify(error={"code": "MISSING_URL", "message": "No URL provided."}, request_id=g.request_id), 400

    from app.security.urls import validate_url
    from utils.url_features import extract_advanced_url_features
    from utils.url_indicators import analyze_url_indicators

    url = validate_url(data["url"], current_app.config["MAX_URL_LENGTH"])
    features = extract_advanced_url_features(url)
    indicators_res = analyze_url_indicators(url, features)

    return jsonify({
        "url": url,
        "features": features,
        "feature_version": "5.1.1",
        "indicators": indicators_res["indicators"],
        "indicator_count": indicators_res["indicator_count"],
        "total_risk_score": indicators_res["total_risk_score"],
        "risk_level": indicators_res["risk_level"]
    })


@bp.post("/api/v1/intelligence/domain")
def domain_intelligence_endpoint():
    data = request.get_json()
    if not isinstance(data, dict) or set(data) - {"url"}:
        raise BadRequest()
    if "url" not in data or not data["url"]:
        return jsonify(error={"code": "MISSING_URL", "message": "No URL provided."}, request_id=g.request_id), 400

    from app.security.urls import validate_url
    from utils.domain_intelligence import analyze_domain_intelligence

    url = validate_url(data["url"], current_app.config["MAX_URL_LENGTH"])
    intel = analyze_domain_intelligence(url)

    return jsonify({
        "url": url,
        "domain_intelligence": intel
    })


@bp.post("/api/v1/analyze/webpage")
def analyze_webpage_endpoint():
    data = request.get_json()
    if not isinstance(data, dict) or set(data) - {"url"}:
        raise BadRequest()
    if "url" not in data or not data["url"]:
        return jsonify(error={"code": "MISSING_URL", "message": "No URL provided."}, request_id=g.request_id), 400

    from app.security.urls import validate_url
    from utils.web_intelligence import analyze_web_intelligence

    url = validate_url(data["url"], current_app.config["MAX_URL_LENGTH"])
    web_intel = analyze_web_intelligence(url)
    from app.behavior.privacy import sanitize_public_web
    sanitize_public_web(web_intel, web_intel.get("_analysis_target", url))
    from app.behavior.privacy import redact_url

    return jsonify({
        "web_intelligence": web_intel,
        "url": redact_url(url)
    })


# ---------- Phase 5 ML Inference Endpoint ----------

@bp.post("/api/v1/ml/predict")
def ml_predict_endpoint():
    """
    Phase 5 §44: Safe ML prediction endpoint.

    Accepts:
      {
        "features": { "<feature_name>": float_value, ... },
        "include_explanations": true,   // optional
        "explanation_top_k": 5          // optional
      }

    Returns either an OK prediction (§43 example shape) or an explicit error
    with one of the §45 error codes. The endpoint never returns "SAFE" on
    model failure — it always returns a 5xx / 4xx error.

    NOTE: Training endpoints are intentionally not exposed via the public API.
    Training must be offline / admin-controlled (§44).
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        body = {
            "error_code": "INVALID_JSON_BODY",
            "error": {"code": "INVALID_JSON_BODY", "message": "Request body must be a JSON object."},
            "request_id": g.request_id,
        }
        return jsonify(body), 400

    if "features" not in data or not isinstance(data["features"], dict):
        body = {
            "error_code": "MISSING_FEATURES",
            "error": {"code": "MISSING_FEATURES", "message": "Body must contain a 'features' object of feature_name -> float."},
            "request_id": g.request_id,
        }
        return jsonify(body), 400

    if set(data) - {"features", "include_explanations", "explanation_top_k", "feature_schema_version"}:
        raise BadRequest()
    if data.get("feature_schema_version", "5.1.1") != "5.1.1":
        return jsonify(error={"code":"FEATURE_SCHEMA_MISMATCH", "message":"Unsupported feature schema."},request_id=g.request_id),400
    include_explanations = data.get("include_explanations", True)
    if not isinstance(include_explanations, bool):
        raise BadRequest()
    if type(data.get("explanation_top_k", 5)) is not int:
        raise BadRequest()
    try:
        top_k = int(data.get("explanation_top_k", 5))
    except (TypeError, ValueError):
        raise BadRequest() from None
    if not 1 <= top_k <= 10:
        raise BadRequest()

    # Fetch predictor — instantiated on demand via app extensions singleton,
    # analogous to how scan_url uses current_app.extensions["models"].
    predictor = current_app.extensions.get("ml_predictor")
    if predictor is None:
        # Lazy initialize (this matches Phase 5 §42/§45 rules: on failure,
        # explicit error rather than silently SAFE.)
        try:
            from ml.inference import SecureSightPredictor
            predictor = SecureSightPredictor()
            load_res = predictor.load()
            if load_res.get("status") != "OK":
                body = {
                    "error_code": load_res.get("status", "MODEL_LOAD_FAILED"),
                    "error": {
                        "code": load_res.get("status", "MODEL_LOAD_FAILED"),
                        "message": "Compatible model artifacts are unavailable.",
                    },
                    "request_id": g.request_id,
                }
                return jsonify(body), 503
            current_app.extensions["ml_predictor"] = predictor
        except Exception:
            body = {
                "error_code": "MODEL_LOAD_FAILED",
                "error": {"code": "MODEL_LOAD_FAILED", "message": "Compatible model artifacts are unavailable."},
                "request_id": g.request_id,
            }
            return jsonify(body), 503

    result = predictor.predict(
        data["features"],
        include_explanations=include_explanations,
        explanation_top_k=top_k,
    )

    status = result.get("status")
    if status != "OK":
        # Map Phase 5 §45 error codes to appropriate HTTP status
        http_status = 500
        if status in ("FEATURE_SCHEMA_MISMATCH", "INVALID_FEATURE_VECTOR",
                      "MISSING_REQUIRED_FEATURE", "PREPROCESSING_FAILED"):
            http_status = 400
        elif status in ("MODEL_NOT_FOUND", "MODEL_LOAD_FAILED", "MODEL_VERSION_MISMATCH"):
            http_status = 503
        elif status == "PREDICTION_FAILED":
            http_status = 500
        err_body = {
            "error_code": status,
            "prediction": None,
            "probability": None,
            "error": {
                "code": status,
                "message": "Feature validation or model prediction failed.",
            },
            "request_id": g.request_id,
        }
        return jsonify(err_body), http_status

    ok_body = dict(result)
    ok_body["request_id"] = g.request_id
    return jsonify(ok_body), 200


@bp.post("/api/analyze")
def legacy_scan():

    return _scan()



@bp.get("/api/v1/health")
def health():
    return jsonify(status="healthy")


@bp.get("/api/v1/ready")
def ready():
    predictor = current_app.extensions.get("ml_predictor")
    available = current_app.extensions["models"]["url"] is not None and predictor is not None and predictor._loaded and predictor.model is not None
    available = available and current_app.extensions.get("risk_engine") is not None
    try:
        available = available and current_app.extensions["scan_limiter"].storage.check()
    except Exception:
        available = False
    return jsonify(status="ready" if available else "unavailable"), 200 if available else 503
