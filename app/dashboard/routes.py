"""Private Phase 12 API and same-origin analyst UI."""
import json
import secrets
from datetime import datetime
from flask import Blueprint, current_app, g, jsonify, render_template, request, session, redirect, Response
from werkzeug.exceptions import BadRequest, NotFound, ServiceUnavailable, Conflict
from .auth import require, csrf
from .store import now, STATUSES, LABELS
from .contracts import query_term
from .service import analytics

bp = Blueprint("dashboard", __name__)
WRITE = ("ADMIN", "ANALYST", "API_CLIENT")


def store():
    value = current_app.extensions.get("dashboard_store")
    if value is None:
        raise ServiceUnavailable()
    return value


def principal():
    return g.dashboard_principal


def body(keys):
    data = request.get_json()
    if not isinstance(data, dict) or set(data) - set(keys):
        raise BadRequest()
    return data


def text(value, maximum=256):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise BadRequest()
    return value.strip()


def paging():
    try:
        limit, offset = int(request.args.get("limit", 25)), int(request.args.get("offset", 0))
    except ValueError:
        raise BadRequest() from None
    if not 1 <= limit <= 100 or not 0 <= offset <= 2000:
        raise BadRequest()
    return limit, offset


def filters():
    allowed = {"limit", "offset", "verdict", "severity", "entity_type", "status", "since", "until", "confidence_min", "q", "source", "evidence_type", "brand", "domain"}
    if set(request.args) - allowed or any(len(request.args.getlist(k)) != 1 for k in request.args):
        raise BadRequest()
    data = {key: text(request.args[key], 256) for key in allowed - {"limit", "offset"} if key in request.args}
    for key in ("since", "until"):
        if key in data:
            try:
                parsed = datetime.fromisoformat(data[key].replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError()
                from datetime import timezone
                data[key] = parsed.astimezone(timezone.utc).isoformat()
            except ValueError:
                raise BadRequest() from None
    if "confidence_min" in data:
        try:
            data["confidence_min"] = float(data["confidence_min"])
            if not 0 <= data["confidence_min"] <= 100:
                raise ValueError()
        except ValueError:
            raise BadRequest() from None
    if data.get("q"):
        data["q"] = query_term(data["q"])
    return data


def investigation(identity, audit=True):
    value = store().get(principal(), identity, audit=audit)
    if value is None:
        raise NotFound()
    return value


@bp.route("/dashboard", defaults={"identity": None}, methods=["GET", "POST"])
@bp.route("/dashboard/<path:identity>", methods=["GET", "POST"])
def scanner_only(identity):
    """The public product is the no-login scanner; analyst UI routes are retired."""
    return redirect("/", code=302)


@bp.get("/api/v1/dashboard/session")
@require()
def session_info():
    return jsonify(contract_version="12.0", user={k: principal()[k] for k in ("username", "role", "tenant")}, csrf_token=csrf() if not g.dashboard_bearer else None,
                   policy=current_app.extensions["risk_engine"].config, session_expires_at=session.get("dashboard_expires"))


@bp.get("/api/v1/dashboard/summary")
@require()
def summary():
    return jsonify(analytics(store(), principal(), filters()))


@bp.get("/api/v1/investigations")
@require()
def investigations():
    limit, offset = paging()
    return jsonify(contract_version="12.0", **store().listing(principal(), filters(), limit, offset))


@bp.get("/api/v1/investigations/compare")
@require()
def compare():
    if set(request.args) != {"a", "b"}:
        raise BadRequest()
    a, b = investigation(request.args["a"]), investigation(request.args["b"])
    return jsonify(contract_version="12.0", investigations=[a, b], compatible_entity_types=a["entity_type"] == b["entity_type"],
                   warning=None if a["entity_type"] == b["entity_type"] else "Different entity types; missing fields are not comparable.")


@bp.get("/api/v1/investigations/<identity>")
@require()
def detail(identity):
    return jsonify(investigation(identity))


@bp.get("/api/v1/investigations/<identity>/evidence")
@require()
def evidence(identity):
    allowed = {"category", "severity", "source", "phase", "evidence_type", "confidence_min", "since", "until", "limit", "offset"}
    if set(request.args) - allowed:
        raise BadRequest()
    limit, offset = paging()
    rows = investigation(identity)["evidence"]
    for key in allowed - {"limit", "offset", "confidence_min", "since", "until"}:
        if request.args.get(key):
            rows = [r for r in rows if str(r.get(key)) == request.args[key]]
    for key, op in (("since", ">="), ("until", "<=")):
        if request.args.get(key):
            # Evidence timestamps remain source timestamps; missing timestamps do not match a time filter.
            try:
                bound = datetime.fromisoformat(request.args[key].replace("Z", "+00:00"))
                if bound.tzinfo is None:
                    raise ValueError()
                def matches(row):
                    try:
                        observed = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                        return observed >= bound if op == ">=" else observed <= bound
                    except (ValueError, TypeError, KeyError):
                        return False
                rows = [r for r in rows if matches(r)]
            except ValueError:
                raise BadRequest() from None
    if request.args.get("confidence_min"):
        try:
            minimum = float(request.args["confidence_min"])
            if not 0 <= minimum <= 1:
                raise ValueError()
        except ValueError:
            raise BadRequest() from None
        rows = [r for r in rows if r.get("confidence") is not None and r["confidence"] >= minimum]
    return jsonify(contract_version="12.0", items=rows[offset:offset + limit], total=len(rows), limit=limit, offset=offset)


@bp.get("/api/v1/investigations/<identity>/timeline")
@require()
def timeline(identity):
    limit, offset = paging()
    rows = investigation(identity)["timeline"]
    return jsonify(contract_version="12.0", items=rows[offset:offset + limit], total=len(rows))


@bp.get("/api/v1/investigations/<identity>/graph")
@require()
def graph(identity):
    limit, offset = paging()
    data = investigation(identity)["graph"]
    nodes = [n for n in data["nodes"] if not request.args.get("type") or n.get("type") == request.args["type"]]
    selected = nodes[offset:offset + limit]
    ids = {n["id"] for n in selected}
    edges = [e for e in data["edges"] if e["source"] in ids and e["target"] in ids]
    return jsonify(contract_version="12.0", nodes=selected, edges=edges, total_nodes=len(nodes), total_edges=len(data["edges"]), omitted_edges=len(data["edges"]) - len(edges))


@bp.get("/api/v1/entities/search")
@require()
def search():
    limit, offset = paging()
    query = query_term(text(request.args.get("q"), 256))
    return jsonify(contract_version="12.0", items=store().entities(principal(), query, limit, offset), matching="NORMALIZED_EXACT", limit=limit, offset=offset)


@bp.get("/api/v1/analytics/trends")
@require()
def trends():
    return jsonify(analytics(store(), principal(), filters()))


@bp.route("/api/v1/cases", methods=["GET", "POST"])
@require()
def cases():
    if request.method == "GET":
        limit, offset = paging()
        return jsonify(contract_version="12.0", items=store().case_list(principal(), limit, offset), limit=limit, offset=offset)
    if principal()["role"] not in WRITE:
        from werkzeug.exceptions import Forbidden
        raise Forbidden()
    data = body({"title", "investigation_ids"})
    ids = data.get("investigation_ids", [])
    if not isinstance(ids, list) or len(ids) > 20 or any(not isinstance(i, str) for i in ids):
        raise BadRequest()
    for identity in ids:
        investigation(identity, audit=False)
    case = {"id": secrets.token_hex(16), "created_at": now(), "updated_at": now(), "title": text(data.get("title"), 160),
            "status": "NEW", "reviewed": False, "tags": [], "investigation_ids": list(dict.fromkeys(ids)), "evidence_references": [], "notes": [], "revision": 1}
    with store().transaction():
        if store().db.execute("SELECT count(*) FROM cases WHERE tenant=?", (principal()["tenant"],)).fetchone()[0] >= 500:
            raise ServiceUnavailable()
        store().case_save(principal(), case)
        store().audit(principal(), "CASE_CREATED", case["id"])
    return jsonify(case), 201


def case(identity):
    value = store().case_get(principal(), identity)
    if value is None:
        raise NotFound()
    return value


@bp.get("/api/v1/cases/<identity>")
@require()
def case_detail(identity):
    with store().lock:
        return jsonify(case(identity))


@bp.post("/api/v1/cases/<identity>")
@require(*WRITE)
def case_update(identity):
    data = body({"status", "reviewed", "tags", "investigation_ids", "evidence_references", "revision"})
    with store().transaction():
        value = case(identity)
        if type(data.get("revision")) is not int or data.get("revision") != value["revision"]:
            raise Conflict()
        if "status" in data:
            if not isinstance(data["status"], str) or data["status"] not in STATUSES:
                raise BadRequest()
            value["status"] = data["status"]
        if "reviewed" in data:
            if type(data["reviewed"]) is not bool:
                raise BadRequest()
            value["reviewed"] = data["reviewed"]
        if "tags" in data:
            if not isinstance(data["tags"], list) or len(data["tags"]) > 12:
                raise BadRequest()
            value["tags"] = [text(t, 48) for t in data["tags"]]
        if "investigation_ids" in data:
            if not isinstance(data["investigation_ids"], list) or len(data["investigation_ids"]) > 20:
                raise BadRequest()
            for item in data["investigation_ids"]:
                if not isinstance(item, str):
                    raise BadRequest()
                investigation(item, audit=False)
            value["investigation_ids"] = list(dict.fromkeys(data["investigation_ids"]))
        if "evidence_references" in data:
            refs = data["evidence_references"]
            if not isinstance(refs, list) or len(refs) > 64:
                raise BadRequest()
            for ref in refs:
                if not isinstance(ref, dict) or set(ref) != {"investigation_id", "evidence_id"} or not all(isinstance(v, str) for v in ref.values()) or ref["investigation_id"] not in value["investigation_ids"]:
                    raise BadRequest()
                if ref["evidence_id"] not in {e["evidence_id"] for e in investigation(ref["investigation_id"], audit=False)["evidence"]}:
                    raise BadRequest()
            value["evidence_references"] = refs
        value.update(updated_at=now(), revision=value["revision"] + 1)
        store().case_save(principal(), value)
        store().audit(principal(), "CASE_CHANGED", identity)
    return jsonify(value)


@bp.post("/api/v1/cases/<identity>/notes")
@require(*WRITE)
def note(identity):
    data = body({"text", "revision"})
    with store().transaction():
        value = case(identity)
        if type(data.get("revision")) is not int or data.get("revision") != value["revision"]:
            raise Conflict()
        if len(value["notes"]) >= 100:
            raise BadRequest()
        value["notes"].append({"id": secrets.token_hex(8), "type": "ANALYST_NOTE", "text": text(data.get("text"), 4000), "author": principal()["username"], "timestamp": now()})
        value.update(updated_at=now(), revision=value["revision"] + 1)
        store().case_save(principal(), value)
        store().audit(principal(), "NOTE_ADDED", identity)
    return jsonify(value), 201


@bp.post("/api/v1/investigations/<identity>/feedback")
@require(*WRITE)
def feedback(identity):
    data = body({"feedback", "status", "tags"})
    with store().transaction():
        value = investigation(identity, audit=False)
        label = data.get("feedback", "UNKNOWN")
        if not isinstance(label, str) or label not in LABELS or not isinstance(data.get("status", "NEW"), str) or data.get("status", "NEW") not in STATUSES:
            raise BadRequest()
        tags = data.get("tags", [])
        if not isinstance(tags, list) or len(tags) > 12:
            raise BadRequest()
        value["analyst_assessment"] = {"feedback": label, "status": data.get("status", "NEW"), "tags": [text(t, 48) for t in tags], "author": principal()["username"], "timestamp": now(), "validated_ground_truth": False}
        value["updated_at"] = now()
        store().db.execute("UPDATE investigations SET data=?,updated_at=? WHERE tenant=? AND id=?", (store().encrypt(value), value["updated_at"], principal()["tenant"], identity))
        store().audit(principal(), "LABEL_CHANGED", identity)
    return jsonify(value["analyst_assessment"])


@bp.get("/api/v1/investigations/<identity>/export")
@require(*WRITE)
def export(identity):
    value = investigation(identity)
    with store().transaction():
        notes = []
        for c in store().case_list(principal(), 500, 0):
            if identity in c["investigation_ids"]:
                notes.extend(c["notes"])
        store().audit(principal(), "REPORT_EXPORTED", identity)
    report = {"investigation": value, "analyst_notes": notes[:500], "methodology": "Phase 2–11 backend evidence; Phase 6 verdict and Phase 7 explanations. Notes and feedback are unvalidated analyst assessments and do not affect scoring."}
    fmt = request.args.get("format", "json")
    if fmt not in {"json", "html"}:
        raise BadRequest()
    data = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False)
    if len(data.encode()) > 2 * 1024 * 1024:
        raise ServiceUnavailable()
    response = Response(data if fmt == "json" else render_template("dashboard_export.html", report=report, data=data), mimetype="application/json" if fmt == "json" else "text/html")
    response.headers["Content-Disposition"] = 'attachment; filename="investigation-' + value["investigation_id"] + '.' + fmt + '"'
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    return response


@bp.get("/api/v1/dashboard/audit")
@require("ADMIN")
def audit():
    limit, offset = paging()
    with store().lock:
        rows = store().db.execute("SELECT seq,event,signature FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT ? OFFSET ?", (principal()["tenant"], limit, offset)).fetchall()
        return jsonify(items=[{"sequence": r[0], "event": json.loads(r[1]), "signature": r[2]} for r in rows], chain_valid=store().verify_audit(), limitations="HMAC detects edits; external anchoring is required to detect complete tail truncation.")
