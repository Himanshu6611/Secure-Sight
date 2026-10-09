"""Phase 12 tenant isolation, evidence truthfulness, workflows and resource tests."""
import copy
import hashlib
import io
import json
import time
import pytest
from werkzeug.security import generate_password_hash
from app.dashboard.contracts import project, query_term, clean
from app.dashboard.service import capture
from app.dashboard.store import Store
from tests.explanation.test_engine import observations
from tests.test_phase11_email import local_pipeline, email

PASSWORD = "test-private-password-12345"
PASSWORD_HASH = generate_password_hash(PASSWORD)


@pytest.fixture
def accounts(app, monkeypatch):
    monkeypatch.setattr("app.dashboard.store.generate_password_hash", lambda value: PASSWORD_HASH)
    store = app.extensions["dashboard_store"]
    for username, tenant, role in [("analyst", "team-a", "ANALYST"), ("viewer", "team-a", "VIEWER"), ("admin", "team-a", "ADMIN"), ("other", "team-b", "ADMIN")]:
        store.provision(username, PASSWORD, role, tenant)
    with store.lock:
        return {row["username"]: store.user(row["id"]) for row in store.db.execute("SELECT id,username FROM users")}


def authenticate(client, account):
    with client.session_transaction() as session:
        session.update(dashboard_user=account["id"], dashboard_expires=time.time() + 3600, dashboard_csrf="test-csrf-token")
    return {"X-CSRF-Token": "test-csrf-token"}


@pytest.fixture
def url_result(app):
    context = observations()
    risk = app.extensions["risk_engine"].calculate(context)
    explanation = app.extensions["explanation_engine"].explain(risk, context["ml_result"], context["web_intelligence"])
    return {"url": "https://example.com/login?token=PRIVATE_QUERY", "status": "PARTIAL", "assessment": risk,
            "explanation": explanation, "ml_probability": .99, "model_version": "5.1.1", "feature_schema_version": "5.1.1",
            "domain_intelligence": context["domain_intelligence"], "web_intelligence": context["web_intelligence"],
            "brand_feature_version": "9.0.0", "brand_intelligence": {"primary_brand": "paypal", "historical_analysis": {"status": "UNAVAILABLE"},
              "evidence_graph": {"nodes": [{"id": "domain", "type": "DOMAIN", "value": "example.com"}, {"id": "brand", "type": "BRAND", "value": "paypal"}], "edges": [{"source": "brand", "target": "domain", "relationship": "CLAIMS_BRAND"}]}}}


@pytest.fixture
def saved(app, accounts, url_result):
    with app.app_context():
        identity = capture(url_result, "URL", accounts["analyst"])
    assert identity
    return identity


@pytest.mark.parametrize("path", ["/api/v1/dashboard/summary", "/api/v1/investigations", "/api/v1/cases", "/api/v1/entities/search?q=example.com", "/api/v1/analytics/trends", "/api/v1/dashboard/audit"])
def test_authentication_required(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path).headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("suffix", ["", "/evidence", "/timeline", "/graph", "/export"])
def test_cross_tenant_idor(client, accounts, saved, suffix):
    authenticate(client, accounts["other"])
    assert client.get(f"/api/v1/investigations/{saved}{suffix}").status_code == 404
    assert client.get("/api/v1/investigations").json["total"] == 0
    assert client.get("/api/v1/entities/search?q=example.com").json["items"] == []
    assert client.get("/api/v1/dashboard/summary").json["total_scans"] == 0


def test_analyst_login_ui_is_removed_and_scanner_stays_public(client, accounts):
    for path in ("/dashboard", "/dashboard/login", "/dashboard/logout", "/dashboard/investigations/example"):
        response = client.get(path)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/")
    login = client.post("/dashboard/login", data={"username": "analyst", "password": PASSWORD})
    assert login.status_code == 302
    assert client.get("/api/v1/dashboard/session").status_code == 401
    assert client.get("/").status_code == 200
    assert b"Analyst sign in" not in client.get("/").data


def test_api_session_expiry_remains_enforced(client, accounts):
    authenticate(client, accounts["analyst"])
    with client.session_transaction() as session:
        session["dashboard_expires"] = 0
    assert client.get("/api/v1/dashboard/session").status_code == 401


def test_server_roles_deactivation_and_export(client, app, accounts, saved):
    headers = authenticate(client, accounts["viewer"])
    assert client.get(f"/api/v1/investigations/{saved}").status_code == 200
    assert client.get(f"/api/v1/investigations/{saved}/export").status_code == 403
    assert client.post("/api/v1/cases", json={"title": "Case"}, headers=headers).status_code == 403
    assert client.post(f"/api/v1/investigations/{saved}/feedback", json={"feedback": "FALSE_POSITIVE"}, headers=headers).status_code == 403
    assert client.get("/api/v1/dashboard/audit").status_code == 403
    store = app.extensions["dashboard_store"]
    with store.transaction():
        store.db.execute("UPDATE users SET active=0 WHERE id=?", (accounts["viewer"]["id"],))
    assert client.get(f"/api/v1/investigations/{saved}").status_code == 401


def test_api_client_bearer_no_cookie_or_csrf(app, client, saved, accounts):
    store = app.extensions["dashboard_store"]
    token = store.provision("automation", PASSWORD, "API_CLIENT", "team-a")
    headers = {"Authorization": "Bearer " + token}
    assert client.get("/api/v1/dashboard/summary", headers=headers).status_code == 200
    assert client.post("/api/v1/cases", json={"title": "Automated case", "investigation_ids": [saved]}, headers=headers).status_code == 201
    assert client.get("/api/v1/dashboard/session", headers={"Authorization": "Bearer wrong"}).status_code == 401
    with store.lock:
        assert token not in json.dumps([dict(row) for row in store.db.execute("SELECT * FROM users")])


def test_authoritative_projection_unchanged(app, url_result):
    before = copy.deepcopy(url_result)
    record, entities = project(url_result, "URL")
    assert url_result == before
    for key in ("verdict", "severity", "risk_score", "confidence", "analysis_completeness", "evidence_coverage"):
        assert record["summary"][key] == before["assessment"][key]
    assert "PRIVATE_QUERY" not in json.dumps(record)
    assert record["summary"]["ml_probability"] == .99
    assert record["contradictions"] == [{"context": "root", "data": c} for c in before["assessment"]["contradictions"] + before["explanation"]["contradictions"]]
    assert all(r["evidence_references"] for r in record["explanations"] if r.get("signal_id") in {e["signal_id"] for e in before["assessment"]["signals"]})
    assert {e["evidence_type"] for e in record["evidence"]} >= {"MODEL_DERIVED", "EXTERNAL"}
    assert {e["type"] for e in entities} >= {"DOMAIN", "URL", "INVESTIGATION"}


@pytest.mark.parametrize("state", ["FAILED", "PARTIAL", "ERROR", "UNAVAILABLE"])
def test_missing_probability_not_safe(client, app, accounts, state):
    result = {"analysis_status": state, "assessment": {"verdict": "UNKNOWN", "risk_score": None, "confidence": None}}
    with app.app_context():
        identity = capture(result, "MEDIA", accounts["analyst"])
    authenticate(client, accounts["analyst"])
    data = client.get(f"/api/v1/investigations/{identity}").json
    assert data["summary"]["verdict"] == "UNKNOWN"
    assert data["summary"]["risk_score"] is None
    assert data["summary"]["confidence"] is None
    assert data["summary"]["ml_probability"] is None
    stats = client.get("/api/v1/dashboard/summary").json
    assert stats["confidence_distribution"]["UNKNOWN"] == 1
    assert stats["deepfake_detections"] is None
    assert stats["unknown_or_partial"] == 1


def test_encrypted_at_rest_reopen_and_wrong_key(tmp_path, app, accounts, url_result):
    path = str(tmp_path / "private.sqlite3")
    store = Store(path, "test-private-encryption-key")
    record, entities = project(url_result, "URL")
    record["subject"] = "PRIVATE_SUBJECT_489"
    store.save(accounts["analyst"], record, entities)
    raw = b''.join(p.read_bytes() for p in tmp_path.iterdir())
    assert b"PRIVATE_SUBJECT_489" not in raw and b"example.com" not in raw
    store.db.close()
    reopened = Store(path, "test-private-encryption-key")
    assert reopened.get(accounts["analyst"], record["investigation_id"])["subject"] == "PRIVATE_SUBJECT_489"
    assert reopened.verify_audit()
    reopened.db.close()
    wrong = Store(path, "different-key")
    with pytest.raises(Exception):
        wrong.get(accounts["analyst"], record["investigation_id"])
    wrong.db.close()


def test_search_filters_pagination_and_sql_injection(client, accounts, saved):
    authenticate(client, accounts["analyst"])
    assert client.get("/api/v1/investigations?q=example.com").json["total"] == 1
    assert client.get("/api/v1/investigations?q=example.com&entity_type=EMAIL").json["total"] == 0
    assert client.get("/api/v1/investigations?source=phase_3_dns&evidence_type=MODEL_DERIVED&brand=paypal&domain=example.com").json["total"] == 1
    assert client.get("/api/v1/investigations?source=unknown_source").json["total"] == 0
    assert client.get("/api/v1/investigations?offset=1&limit=1").json["total"] == 1
    assert client.get("/api/v1/investigations?verdict=%27%20OR%201=1--").json["total"] == 0
    results = client.get("/api/v1/entities/search?q=example.com").json["items"]
    assert any(r["entity_type"] == "DOMAIN" and r["investigation_id"] == saved for r in results)
    assert query_term("a@example.com") == hashlib.sha256(b"a@example.com").hexdigest()
    assert query_term("<id@example.com>") == hashlib.sha256(b"<id@example.com>").hexdigest()


@pytest.mark.parametrize("query", ["limit=101", "offset=-1", "limit=bad", "confidence_min=NaN", "since=nope", "since=2026-10-08", "tenant=team-b", "q=x&q=y"])
def test_oversized_and_malformed_queries(client, accounts, query):
    authenticate(client, accounts["analyst"])
    assert client.get("/api/v1/investigations?" + query).status_code == 400


def test_evidence_graph_timeline_pagination(client, accounts, saved):
    authenticate(client, accounts["analyst"])
    evidence = client.get(f"/api/v1/investigations/{saved}/evidence?evidence_type=MODEL_DERIVED").json
    assert evidence["items"] and all(e["evidence_type"] == "MODEL_DERIVED" for e in evidence["items"])
    assert client.get(f"/api/v1/investigations/{saved}/evidence?confidence_min=nan").status_code == 400
    graph = client.get(f"/api/v1/investigations/{saved}/graph?type=DOMAIN&limit=1").json
    assert len(graph["nodes"]) == 1 and graph["nodes"][0]["type"] == "DOMAIN"
    assert graph["edges"] == [] and graph["omitted_edges"] == 1
    timeline = client.get(f"/api/v1/investigations/{saved}/timeline").json
    assert timeline["items"][-1]["source"] == "phase_12"


def test_cases_notes_evidence_feedback_and_no_score_mutation(client, app, accounts, saved):
    headers = authenticate(client, accounts["analyst"])
    before = client.get(f"/api/v1/investigations/{saved}").json
    c = client.post("/api/v1/cases", json={"title": "Investigate email", "investigation_ids": [saved]}, headers=headers)
    assert c.status_code == 201
    identity = c.json["id"]
    assert client.post(f"/api/v1/cases/{identity}/notes", json={"text": "x", "revision": 1}).status_code == 403
    note = client.post(f"/api/v1/cases/{identity}/notes", json={"text": '<img src=x onerror="alert(1)">', "revision": 1}, headers=headers)
    assert note.status_code == 201 and note.json["notes"][0]["type"] == "ANALYST_NOTE"
    assert client.post(f"/api/v1/cases/{identity}", json={"revision": 1, "status": "CLOSED"}, headers=headers).status_code == 409
    ref = {"investigation_id": saved, "evidence_id": before["evidence"][0]["evidence_id"]}
    updated = client.post(f"/api/v1/cases/{identity}", json={"revision": 2, "status": "FALSE_POSITIVE", "reviewed": True, "tags": ["triage"], "evidence_references": [ref]}, headers=headers)
    assert updated.status_code == 200
    assert client.post(f"/api/v1/investigations/{saved}/feedback", json={"feedback": "FALSE_POSITIVE", "status": "CLOSED"}, headers=headers).status_code == 200
    after = client.get(f"/api/v1/investigations/{saved}").json
    assert before["summary"] == after["summary"] and before["evidence"] == after["evidence"]
    assert after["analyst_assessment"]["validated_ground_truth"] is False
    report = client.get(f"/api/v1/investigations/{saved}/export?format=html")
    assert report.status_code == 200 and b'<img src=x onerror="alert(1)">' not in report.data
    assert b'&lt;img' in report.data and 'sandbox' in report.headers["Content-Security-Policy"]
    assert report.headers["Content-Disposition"].startswith("attachment;")
    authenticate(client, accounts["other"])
    assert client.get(f"/api/v1/cases/{identity}").status_code == 404
    assert client.post(f"/api/v1/cases/{identity}/notes", json={"text": "x", "revision": 3}, headers=headers).status_code == 404


def test_cross_tenant_case_link_rejected(client, accounts, saved):
    headers = authenticate(client, accounts["other"])
    assert client.post("/api/v1/cases", json={"title": "Hidden", "investigation_ids": [saved]}, headers=headers).status_code == 404


def test_audit_integrity_and_admin_scope(client, app, accounts, saved):
    authenticate(client, accounts["admin"])
    client.get(f"/api/v1/investigations/{saved}")
    data = client.get("/api/v1/dashboard/audit").json
    assert data["chain_valid"] and all(r["event"]["tenant"] == "team-a" for r in data["items"])
    assert any(r["event"]["action"] == "INVESTIGATION_OPENED" for r in data["items"])
    store = app.extensions["dashboard_store"]
    with store.transaction():
        store.db.execute("UPDATE audit SET event='{}' WHERE seq=1")
    assert not store.verify_audit()
    assert app.test_cli_runner().invoke(args=["dashboard-audit-check"]).exit_code == 1


def test_capture_scans_only_authenticated_and_no_rerun(client, app, accounts, url_result, monkeypatch):
    calls = []
    monkeypatch.setattr("app.api.v1.scan_url", lambda url: calls.append(url) or copy.deepcopy(url_result))
    anonymous = client.post("/api/v1/scan", json={"url": "https://example.com"})
    assert anonymous.status_code == 200 and "investigation_id" not in anonymous.json
    headers = authenticate(client, accounts["analyst"])
    response = client.post("/api/v1/scan", json={"url": "https://example.com"}, headers=headers)
    assert response.status_code == 200 and response.json["investigation_id"]
    assert calls == ["https://example.com", "https://example.com"]
    assert client.get("/api/v1/dashboard/summary").json["total_scans"] == 1
    assert client.post("/api/v1/scan", json={"url": "https://example.com"}).status_code == 403


def test_owned_async_email_capture(client, app, accounts, local_pipeline):
    headers = authenticate(client, accounts["analyst"])
    response = client.post("/api/v1/email/analyze", json={"raw_email": email("Urgent invoice new bank account", reply="payment@example.net").as_string()}, headers=headers)
    assert response.status_code == 202
    job = response.json
    for _ in range(100):
        poll = client.get(job["poll_url"], headers={"Authorization": "Bearer " + job["token"]})
        if poll.json["result"]:
            break
        time.sleep(.01)
    result = poll.json["result"]
    identity = result["investigation_id"]
    detail = client.get(f"/api/v1/investigations/{identity}").json
    assert detail["summary"]["verdict"] == result["risk"]["verdict"]
    assert detail["panels"]["Authentication"][0]["data"]["spf"]["result"] == "UNAVAILABLE"
    assert "PRIVATE_BODY_NOT_RETAINED" in json.dumps(detail)
    authenticate(client, accounts["other"])
    assert client.get(f"/api/v1/investigations/{identity}").status_code == 404


def test_comparison_and_analyst_page_redirect(client, app, accounts, saved, url_result):
    authenticate(client, accounts["analyst"])
    with app.app_context():
        other = capture({"artifact": {"sha256": "a" * 64}, "analysis_status": "PARTIAL", "assessment": {"verdict": "UNKNOWN"}}, "MEDIA", accounts["analyst"])
    compared = client.get(f"/api/v1/investigations/compare?a={saved}&b={other}")
    assert compared.status_code == 200 and not compared.json["compatible_entity_types"] and compared.json["warning"]
    page = client.get(f"/dashboard/investigations/{saved}")
    assert page.status_code == 302 and page.headers["Location"].endswith("/")


def test_record_size_caps_and_original_content_omission():
    result = {"raw_email": "secret", "raw_html": "<script>x</script>", "token": "secret", "body_analysis": {"snippet": "private"},
              "assessment": {"verdict": "UNKNOWN"}, "message": {"headers": {"subject": "x" * 100000}}, "graph": {"nodes": [{"id": str(i), "type": "DOMAIN"} for i in range(2000)], "edges": []}}
    record, entities = project(result, "EMAIL")
    assert len(record["graph"]["nodes"]) <= 512
    assert len(record["subject"]) <= 2048
    assert len(json.dumps(record)) < 1024 * 1024
    assert clean({"_data": "secret", "raw_html": "evil", "snippet": "private"}) == {"snippet": "PRIVATE_BODY_NOT_RETAINED"}


def test_operator_cli_and_production_fail_closed(app, runner=None):
    result = app.test_cli_runner().invoke(args=["dashboard-user", "--username", "operator", "--tenant", "team", "--role", "ADMIN", "--password", PASSWORD])
    assert result.exit_code == 0 and "Account created" in result.output
    assert app.test_cli_runner().invoke(args=["dashboard-audit-check"]).output.strip() == "VALID"
    assert app.test_cli_runner().invoke(args=["dashboard-disable-user", "--username", "operator"]).exit_code == 0
    assert app.extensions["dashboard_store"].login("operator", PASSWORD) is None
    from app.dashboard.setup import install
    from flask import Flask
    disabled = Flask("disabled")
    disabled.config["APP_ENV"] = "production"
    install(disabled)
    assert disabled.extensions["dashboard_store"] is None


def test_real_email_qr_website_unified_workspace(app, client, accounts, local_pipeline, monkeypatch):
    import cv2
    from PIL import Image, ImageDraw, ImageFont
    from app.services import scans
    from app.email.service import analyze
    context = observations()
    destination = "https://verify-paypal-account.example.net/login"
    monkeypatch.setattr(scans, "analyze_domain_intelligence", lambda url: context["domain_intelligence"])
    monkeypatch.setattr(scans, "analyze_web_intelligence", lambda url: context["web_intelligence"])
    monkeypatch.setattr(local_pipeline, "run_linked", lambda url, ctx, config, *args: scans.scan_url(url, email_context=ctx))
    image = Image.new("RGB", (900, 450), "white")
    image.paste(Image.fromarray(cv2.QRCodeEncoder_create().encode(destination)).resize((350, 350), Image.Resampling.NEAREST), (20, 30))
    ImageDraw.Draw(image).text((405, 70), "PayPal account", font=ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 40), fill="black")
    output = io.BytesIO(); image.save(output, "PNG")
    message = email(destination, sender="PayPal <notice@sender.example.net>")
    message.add_attachment(output.getvalue(), maintype="image", subtype="png", filename="notice.png")
    with app.app_context():
        result = analyze(message.as_bytes())
        identity = capture(result, "EMAIL", accounts["analyst"])
    authenticate(client, accounts["analyst"])
    record = client.get(f"/api/v1/investigations/{identity}").json
    assert record["summary"]["verdict"] == result["risk"]["verdict"]
    assert {"Email", "Authentication", "Media", "Media models", "OCR", "QR", "C2PA", "Website", "Domain", "Brand", "History", "Attachments", "Explanation"} <= set(record["panels"])
    assert {"QR", "DOMAIN", "EMAIL", "IMAGE"} <= {n["type"] for n in record["graph"]["nodes"]}
    assert len(record["graph"]["nodes"]) == len(result["graph"]["nodes"])
    assert sum(e["original_evidence_id"] == "html.external_credentials" for e in record["evidence"]) == 1
    assert record["panels"]["Media models"][0]["data"]["synthetic_probability"] is None
    assert record["explanations"] and record["timeline"]
    assert not any("raw_email" in str(p) for p in record["panels"])


@pytest.mark.parametrize("data", [{"status": []}, {"feedback": {}}, {"feedback": "UNKNOWN", "tags": "bad"}])
def test_malformed_feedback_not_500(client, accounts, saved, data):
    headers = authenticate(client, accounts["analyst"])
    assert client.post(f"/api/v1/investigations/{saved}/feedback", json=data, headers=headers).status_code == 400


def test_realistic_500_record_query_volume(app, client, accounts, url_result):
    store = app.extensions["dashboard_store"]
    record, entities = project(url_result, "URL")
    for i in range(500):
        item = copy.deepcopy(record)
        item["investigation_id"] = f"{i:032x}"
        store.save(accounts["analyst"], item, [])
    authenticate(client, accounts["analyst"])
    started = time.monotonic()
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200 and response.json["total_scans"] == 500
    assert time.monotonic() - started < 5
    page = client.get("/api/v1/investigations?limit=25&offset=475")
    assert len(page.json["items"]) == 25 and page.json["total"] == 500
    assert len(page.data) < 32768


def test_email_severity_uses_existing_phase6_policy(app, local_pipeline):
    from app.email.service import analyze
    from app.risk.verdict import severity
    with app.app_context():
        result = analyze(email("Urgent: pay invoice today to the new bank account", reply="finance@example.net").as_bytes())
    assert result["risk"]["risk_score"] == 60
    assert result["risk"]["severity"] == severity(60, app.extensions["risk_engine"].config) == "HIGH"


def test_telemetry_describes_actual_findings(client, app, accounts, local_pipeline):
    from app.email.service import analyze
    with app.app_context():
        result = analyze(email("Urgent invoice: new bank account", sender="PayPal <finance@example.com>", reply="finance@example.net").as_bytes())
        identity = capture(result, "EMAIL", accounts["analyst"])
    authenticate(client, accounts["analyst"])
    stats = client.get("/api/v1/dashboard/summary").json
    assert stats["telemetry_coverage_records"] == 1 and stats["telemetry_missing_records"] == 0
    assert stats["top_observed_brands"]["paypal"] == 1
    assert stats["bec_patterns"]["BEC_CONTEXT_COMBINATION"] == 1
    assert stats["high_risk_domains"] >= 1
    assert stats["deepfake_detections"] is None
    assert identity


def test_worker_start_failure_releases_capacity(app, monkeypatch):
    from app.email.jobs import EmailJobs
    from app.email.parser import EmailError
    def unavailable(*args):
        raise RuntimeError("Thread failure")
    monkeypatch.setattr("threading.Thread.start", unavailable)
    jobs = EmailJobs()
    for _ in range(3):
        with pytest.raises(EmailError, match="EMAIL_WORKER_UNAVAILABLE"):
            jobs.submit(app, b"test")
    assert jobs.slots.acquire(blocking=False)
    jobs.slots.release()
    assert not jobs.dashboard_active


def test_schema_contract_and_dates(app, url_result):
    from pathlib import Path
    import jsonschema
    result = copy.deepcopy(url_result)
    result["domain_intelligence"]["registration"]["creation_date"] = "2010-01-02"
    record, _ = project(result, "URL")
    schema = json.loads(Path('docs/schemas/investigation_v12.json').read_text())
    jsonschema.validate(record, schema)
    assert any(e["timestamp"] == "2010-01-02" and e["precision"] == "DATE_ONLY" for e in record["timeline"])


def test_private_purge_cli_removes_content_preserves_audit(app, accounts, saved):
    store = app.extensions["dashboard_store"]
    assert app.test_cli_runner().invoke(args=["dashboard-purge", "--tenant", "team-a"]).exit_code == 0
    assert store.get(accounts["analyst"], saved) is None
    assert store.verify_audit()


def test_failed_async_analysis_is_private_history(client, app, accounts, monkeypatch):
    from app.email.parser import EmailError
    def fail(*args, **kwargs):
        raise EmailError("RESOURCE_LIMIT", 422)
    monkeypatch.setattr("app.email.service.analyze", fail)
    headers = authenticate(client, accounts["analyst"])
    job = client.post("/api/v1/email/analyze", json={"raw_email": "Synthetic test"}, headers=headers).json
    for _ in range(100):
        poll = client.get(job["poll_url"], headers={"Authorization": "Bearer " + job["token"]}).json
        if poll["result"]:
            break
        time.sleep(.01)
    assert poll["state"] == "FAILED" and poll["result"]["investigation_id"]
    stats = client.get("/api/v1/dashboard/summary").json
    assert stats["analysis_failures"] == 1 and stats["unknown_or_partial"] == 1
    authenticate(client, accounts["other"])
    assert client.get("/api/v1/dashboard/summary").json["analysis_failures"] == 0


def test_existing_encrypted_snapshot_search_backfill(tmp_path, accounts, url_result):
    path = str(tmp_path / "existing.sqlite3")
    store = Store(path, "private-migration-key")
    record, entities = project(url_result, "URL")
    store.save(accounts["analyst"], record, entities)
    with store.transaction():
        store.db.execute("DELETE FROM entities WHERE kind IN ('SOURCE','EVIDENCE_TYPE')")
    store.db.close()
    reopened = Store(path, "private-migration-key")
    assert reopened.listing(accounts["analyst"], {"source": "phase_3_dns", "evidence_type": "MODEL_DERIVED"})["total"] == 1
    assert reopened.listing(accounts["other"], {"source": "phase_3_dns"})["total"] == 0
    assert reopened.get(accounts["analyst"], record["investigation_id"], audit=False) == record
    assert reopened.verify_audit()
    reopened.db.close()
