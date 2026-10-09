"""Cryptographic fixtures, untrusted headers, MIME bombs and cross-modal integration."""
import base64
import io
import json
import time
import zipfile
from email.message import EmailMessage
import pytest
from app.email.parser import parse, EmailError
from app.email.authentication import analyze as authenticate
from app.email.nlp import analyze as analyze_body
from app.email.attachments import inspect
from app.email.service import analyze


def email(body="Hello", sender="Alice <alice@example.com>", reply=None, subject="Hello"):
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, "recipient@example.org", subject
    if reply:
        message["Reply-To"] = reply
    message.set_content(body)
    return message


def prepared(raw):
    from app.email import service
    result = parse(raw)
    result["authentication"] = authenticate(raw, result["headers"], dns_lookup=lambda *a, **k: None)
    result["body_analysis"] = analyze_body(result.pop("bodies"), result["headers"])
    cleaned = []
    for attachment in result["attachments"]:
        metadata, data = inspect(attachment)
        if metadata["magic"] in {"PNG", "JPEG", "WEBP"}:
            metadata["_data"] = base64.b64encode(data).decode()
        cleaned.append(metadata)
    result["attachments"] = cleaned
    return result


@pytest.fixture
def local_pipeline(monkeypatch):
    from app.email import service
    def bounded(data, artifact, *args, **kwargs):
        return prepared(data) if artifact["mime"] == "--email" else {"status": "ANALYSIS_FAILED"}
    monkeypatch.setattr(service, "run", bounded)
    return service


def test_multipart_charset_and_encoded_headers():
    message = email("नमस्ते", sender="नमस्ते <alice@example.com>", subject="Überprüfung")
    message.add_alternative('<p>नमस्ते <a href="https://example.com/">Portal</a></p>', subtype="html")
    result = parse(message.as_bytes())
    assert len(result["bodies"]) == 2
    assert result["headers"]["subject"] == "Überprüfung"
    assert result["headers"]["from_domain"] == "example.com"


def test_duplicate_identity_is_unknown():
    raw = b"From: alice@example.com\r\nFrom: evil@example.net\r\nSubject: hello\r\n\r\nbody"
    result = parse(raw)
    assert result["headers"]["from_domain"] is None
    assert "from" in result["headers"]["duplicate_headers"]


@pytest.mark.parametrize("raw", [b"", b"x" * (2 * 1024 * 1024 + 1), b"From: " + b"a" * 9000 + b"\r\n\r\nbody", b"\n" * 20001], ids=["empty", "oversized", "long_header", "many_lines"])
def test_parser_limits(raw):
    with pytest.raises(EmailError):
        parse(raw)


def test_mime_depth_limit():
    child = email()
    for _ in range(10):
        parent = EmailMessage(); parent.make_mixed(); parent.attach(child); child = parent
    with pytest.raises(EmailError, match="MIME_RESOURCE_LIMIT"):
        parse(child.as_bytes())


def test_attachment_and_body_limits():
    message = email("a" * 66000)
    with pytest.raises(EmailError, match="BODY_RESOURCE_LIMIT"):
        parse(message.as_bytes())
    message = email()
    message.add_attachment(b"a" * (512 * 1024 + 1), maintype="application", subtype="octet-stream", filename="large.bin")
    with pytest.raises(EmailError, match="ATTACHMENT_RESOURCE_LIMIT"):
        parse(message.as_bytes())


def test_identity_delegation_does_not_prove_phishing():
    message = email(reply="team@service.example.net")
    message["Sender"], message["Return-Path"] = "mailer@provider.example.net", "bounce@provider.example.net"
    headers = parse(message.as_bytes())["headers"]
    assert set(headers["relationships"].values()) == {"MISALIGNED"}
    assert headers["identities"]["from"][0]["mailbox_sha256"]
    assert "alice@" not in json.dumps(headers)


@pytest.mark.parametrize("sender,indicator", [("PayPаl <user@example.net>", "CONFUSABLE_CHARACTERS"),
    ("Pay\u200bPal <user@example.net>", "INVISIBLE_CONTROL"), ("user@xn--bcher-kva.example", "PUNYCODE")])
def test_unicode_identity(sender, indicator):
    assert indicator in parse(email(sender=sender).as_bytes())["headers"]["unicode_indicators"]


@pytest.mark.parametrize("state", ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"])
def test_claims_never_become_verified_spf(state):
    message = email()
    message["Authentication-Results"] = f"mx.google.com; spf={state} smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    raw = message.as_bytes(); result = authenticate(raw, parse(raw)["headers"], dns_lookup=lambda *a, **k: None)
    assert result["claims"][0]["result"] == state.upper()
    assert result["spf"]["result"] == "UNAVAILABLE"
    assert result["dkim"]["result"] == "NONE"
    assert result["dmarc"]["result"] != "PASS"
    assert result["claims_trusted"] is False


@pytest.fixture
def keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, b"v=DKIM1; k=rsa; p=" + base64.b64encode(public)


def test_real_dkim_and_dmarc_alignment(keypair):
    import dkim
    raw = email().as_bytes(policy=__import__("email.policy", fromlist=["SMTP"]).SMTP)
    signature = dkim.sign(raw, b"s1", b"example.com", keypair[0], include_headers=[b"from", b"to", b"subject"])
    signed = signature + raw
    def dns(name, **kwargs):
        return b"v=DMARC1; p=reject; adkim=s" if name.startswith(b"_dmarc") else keypair[1]
    result = authenticate(signed, parse(signed)["headers"], dns_lookup=dns)
    assert result["dkim"]["result"] == "PASS"
    assert result["dmarc"]["result"] == "PASS"
    assert result["spf"]["result"] == "UNAVAILABLE"
    tampered = signed.replace(b"Hello\r\n", b"Stolen\r\n")
    assert authenticate(tampered, parse(tampered)["headers"], dns_lookup=dns)["dkim"]["result"] != "PASS"


def test_dkim_pass_is_not_dmarc_alignment(keypair):
    import dkim
    raw = email().as_bytes()
    signed = dkim.sign(raw, b"s1", b"thirdparty.example.net", keypair[0]) + raw
    result = authenticate(signed, parse(signed)["headers"], dns_lookup=lambda name, **kw: b"v=DMARC1; p=reject" if name.startswith(b"_dmarc") else keypair[1])
    assert result["dkim"]["result"] == "PASS"
    assert result["dkim"]["signatures"][0]["alignment"] == "MISALIGNED"
    assert result["dmarc"]["result"] == "UNAVAILABLE"


def test_real_arc_chain_and_tampering(keypair):
    import dkim
    raw = email().as_bytes()
    raw = b"Authentication-Results: mx.example; dkim=pass header.d=example.com\r\n" + raw
    signed = b"".join(dkim.arc_sign(raw, b"s1", b"example.com", keypair[0], b"mx.example")) + raw
    dns = lambda name, **kw: b"v=DMARC1; p=none" if name.startswith(b"_dmarc") else keypair[1]
    result = authenticate(signed, parse(signed)["headers"], dns_lookup=dns)
    assert result["arc"]["result"] == "PASS"
    assert result["arc"]["chain_trusted"] is False
    changed = signed.replace(b"Hello\n", b"Changed\n")
    assert authenticate(changed, parse(changed)["headers"], dns_lookup=dns)["arc"]["result"] != "PASS"


def test_received_private_ips_and_chronology():
    message = email()
    message["Received"] = "from old.example ([10.0.0.1]) by mx.example; Tue, 06 Oct 2026 10:00:00 +0000"
    message["Received"] = "from source.example ([8.8.8.8]) by old.example; Wed, 07 Oct 2026 10:00:00 +0000"
    result = parse(message.as_bytes())["headers"]["received"]
    assert result["chronology_anomaly"] is True
    assert "10.0.0.1" not in json.dumps(result)
    assert result["trust_boundary_verified"] is False


def test_html_link_mismatch_and_no_rendering():
    message = email()
    message.add_alternative('<a href="https://evil.example/">https://paypal.com/</a><img src="http://127.0.0.1/x"><script>alert(1)</script><p hidden>hidden</p>', subtype="html")
    parsed = parse(message.as_bytes()); result = analyze_body(parsed["bodies"], parsed["headers"])
    assert result["html"]["url_mismatches"]
    assert result["html"]["scripts"] == 1
    assert result["html"]["remote_images"] == 1
    assert "alert(1)" not in result["_text"]


def attachment(data, filename="file.zip", mime="application/zip"):
    return {"filename": filename, "mime": mime, "bytes": len(data), "sha256": "a" * 64, "_data": base64.b64encode(data).decode()}


@pytest.mark.parametrize("filename,data", [("invoice.pdf.exe", b"MZbinary"), ("../../file.png", b"MZbinary"), ("file.docm", b"OLE")])
def test_dangerous_attachment_observed(filename, data):
    result, original = inspect(attachment(data, filename, "application/octet-stream"))
    assert result["indicators"] and result["executed"] is False
    assert original == data
    assert "/" not in result["filename"]


def test_zip_bomb_traversal_nested_and_macro():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../file.txt", "bounded")
        archive.writestr("nested.zip", "nested")
        archive.writestr("word/vbaProject.bin", "macro")
        archive.writestr("bomb.txt", "a" * 100000)
    result, _ = inspect(attachment(stream.getvalue()))
    assert {"ARCHIVE_PATH_TRAVERSAL", "NESTED_ARCHIVE_UNINSPECTED", "MACRO_ATTACHMENT", "ARCHIVE_RESOURCE_LIMIT"} <= set(result["indicators"])
    assert result["archive"]["extracted"] is False


@pytest.mark.parametrize("body", ["Urgent password reset", "Invoice payment due today", "Bank security alert", "New company welcome", "Marketing gift cards sale", "Confidential newsletter for the CEO"])
def test_keywords_alone_never_phishing(app, local_pipeline, body):
    with app.app_context():
        result = analyze(email(body).as_bytes())
    assert result["risk"]["verdict"] == "UNKNOWN"
    assert result["risk"]["risk_score"] is None


def test_bec_requires_combination_with_identity(app, local_pipeline):
    message = email("Urgent wire transfer today. Use our new bank account. Keep this confidential.", reply="ceo@unrelated.example.net")
    with app.app_context():
        result = analyze(message.as_bytes())
    assert result["risk"]["verdict"] == "SUSPICIOUS"
    assert result["risk"]["email_policy"]["floors"][0]["rule"] == "BEC_WITH_IDENTITY_ANOMALY"
    assert result["risk"]["confidence"] is None
    assert all(r["evidence_id"] in {e["evidence_id"] for e in result["evidence"]} for r in result["explanation"]["reasons"])


def test_brand_spoof_is_not_automatic_phishing(app, local_pipeline):
    with app.app_context():
        result = analyze(email(sender="PayPal <user@not-paypal.example.net>").as_bytes())
    assert result["brands"]["display_name_impersonation"] == ["paypal"]
    assert result["risk"]["verdict"] == "UNKNOWN"


def test_url_reuse_dedup_and_private_block(app, local_pipeline, monkeypatch):
    calls = []
    monkeypatch.setattr(local_pipeline, "run_linked", lambda url, *a: calls.append(url) or {})
    with app.app_context():
        result = analyze(email("https://example.com/ https://example.com/#top http://127.0.0.1/private").as_bytes())
    assert calls == ["https://example.com/"]
    assert result["errors"] == [{"code": "EXTRACTED_URL_BLOCKED"}]
    assert result["risk"]["verdict"] == "UNKNOWN"


def test_multiple_email_links_are_scanned_with_a_hard_cap(app, local_pipeline, monkeypatch):
    calls = []
    monkeypatch.setattr(local_pipeline, "run_linked", lambda url, *args, **kwargs: calls.append(url) or {})
    destinations = [f"https://site-{index}.example/path" for index in range(6)]
    with app.app_context():
        result = analyze(email(" ".join(destinations)).as_bytes())
    assert calls == destinations[:5]
    assert sum(item["status"] == "ANALYZED" for item in result["url_inventory"]) == 5
    assert result["url_inventory"][-1]["status"] == "NOT_ANALYZED_RESOURCE_LIMIT"
    assert {"code": "EMAIL_URL_BUDGET_LIMIT"} in result["errors"]


def test_async_api_token_and_failure_safety(client):
    response = client.post("/api/v1/email/analyze", json={"raw_email": "Hello world"})
    assert response.status_code == 202
    job = response.get_json()
    assert client.get(job["poll_url"]).status_code == 404
    assert client.get(job["poll_url"], headers={"Authorization": "Bearer wrong"}).status_code == 404
    for _ in range(100):
        poll = client.get(job["poll_url"], headers={"Authorization": "Bearer " + job["token"]})
        if poll.get_json()["result"]:
            break
        time.sleep(.03)
    result = poll.get_json()["result"]
    assert result["risk"]["verdict"] == "UNKNOWN"
    assert result["analysis_status"] == "PARTIAL"
    assert poll.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("data", [{}, {"raw_email": ""}, {"raw_email": 123}, {"messages": []}, {"raw_email": "Hi", "smtp_peer": "8.8.8.8"}])
def test_api_rejects_forged_context(client, data):
    assert client.post("/api/v1/email/analyze", json=data).status_code == 400


def test_email_media_website_dedup(app, local_pipeline, monkeypatch):
    import cv2
    from PIL import Image, ImageDraw, ImageFont
    from app.services import scans
    from tests.explanation.test_engine import observations
    context = observations()
    destination = "https://verify-paypal-account.example.net/login"
    monkeypatch.setattr(scans, "analyze_domain_intelligence", lambda url: context["domain_intelligence"])
    monkeypatch.setattr(scans, "analyze_web_intelligence", lambda url: context["web_intelligence"])
    calls = []
    def scan(url, email_context, config, wall_seconds=25):
        calls.append(url)
        return scans.scan_url(url, email_context=email_context)
    monkeypatch.setattr(local_pipeline, "run_linked", scan)
    image = Image.new("RGB", (900, 450), "white")
    image.paste(Image.fromarray(cv2.QRCodeEncoder_create().encode(destination)).resize((350, 350), Image.Resampling.NEAREST), (20, 30))
    ImageDraw.Draw(image).text((405, 70), "PayPal account", font=ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 40), fill="black")
    output = io.BytesIO(); image.save(output, "PNG")
    message = email(destination, sender="PayPal <notice@sender.example.net>")
    message.add_attachment(output.getvalue(), maintype="image", subtype="png", filename="notice.png")
    with app.app_context():
        result = analyze(message.as_bytes())
    assert calls == [destination]
    assert result["urls"][0]["sources"] == ["MEDIA", "PLAIN_TEXT"]
    assert result["media"][0]["qr"]["items"]
    assert result["media"][0]["brand_analysis"]["observed_brands"] == ["paypal"]
    assert result["media"][0]["synthetic_media"]["synthetic_probability"] is None
    assert any(n["type"] == "QR" for n in result["graph"]["nodes"])
    assert any(n["type"] == "DOMAIN" for n in result["graph"]["nodes"])
    assert result["risk"]["verdict"] == "SUSPICIOUS"
    assert "_data" not in json.dumps(result)


def test_failed_url_and_media_stages_never_safe(app, local_pipeline, monkeypatch):
    from app.media.intake import MediaError
    def failed(*args):
        raise MediaError("RESOURCE_LIMIT", 422)
    monkeypatch.setattr(local_pipeline, "run_linked", failed)
    with app.app_context():
        result = analyze(email("https://example.com/").as_bytes())
    assert result["risk"]["verdict"] == "UNKNOWN"
    assert result["risk"]["risk_score"] is None
    assert {"code": "URL_RESOURCE_LIMIT"} in result["errors"]


def test_campaign_only_explicit_batch(app, local_pipeline):
    from app.email.service import analyze_batch
    with app.app_context():
        result = analyze_batch([email(subject="Shared newsletter").as_bytes(), email(subject="Shared newsletter").as_bytes()])
    assert result["campaign"]["groups"]
    assert result["campaign"]["scope"] == "ONLY_THIS_EXPLICIT_BATCH"
    assert result["campaign"]["cross_user_store"] is False
    assert result["risk"]["campaign_risk_points"] == 0
    assert "Shared newsletter" not in json.dumps(result["campaign"])


def test_job_queue_backpressure_and_expiry(app, monkeypatch):
    import threading
    from app.email.jobs import EmailJobs
    entered, release = threading.Event(), threading.Event()
    def blocking(raw, **kwargs):
        entered.set(); release.wait(3)
        return {"analysis_status": "PARTIAL", "risk": {"verdict": "UNKNOWN"}}
    monkeypatch.setattr("app.email.service.analyze", blocking)
    jobs = EmailJobs()
    first = jobs.submit(app, b"one")
    second = jobs.submit(app, b"two")
    try:
        assert entered.wait(1)
        with pytest.raises(EmailError, match="EMAIL_QUEUE_FULL"):
            jobs.submit(app, b"three")
        assert jobs.read(first["job_id"], "wrong") is None
    finally:
        release.set()
    for _ in range(100):
        if jobs.read(second["job_id"], second["token"])["result"]:
            break
        time.sleep(.01)
    assert jobs.read(first["job_id"], first["token"])["result"]
    jobs.records[first["job_id"]]["expires"] = 0
    assert jobs.read(first["job_id"], first["token"]) is None


def test_upload_eml_html_and_private_logs(client, app):
    import logging
    capture = io.StringIO()
    handler = app.logger.handlers[0]
    previous = handler.setStream(capture)
    raw = b"Subject: PRIVATE_EMAIL_123\r\n\r\nPRIVATE_BODY_123 <script>alert(1)</script>"
    try:
        response = client.post("/api/v1/email/analyze", data={"file": (io.BytesIO(raw), "test.eml", "message/rfc822")}, content_type="multipart/form-data")
    finally:
        handler.setStream(previous)
    assert response.status_code == 202
    assert response.json["job_id"]
    assert "PRIVATE_EMAIL_123" not in capture.getvalue() and "PRIVATE_BODY_123" not in capture.getvalue()


def test_production_redis_encryption_cross_worker_and_capacity(app, monkeypatch):
    import fakeredis
    import redis
    import threading
    from app.email.jobs import EmailJobs
    server = fakeredis.FakeServer()
    monkeypatch.setattr(redis.Redis, "from_url", lambda *a, **k: fakeredis.FakeRedis(server=server))
    app.config.update(APP_ENV="production", SECRET_KEY="s" * 64)
    first_worker, second_worker = EmailJobs(app), EmailJobs(app)
    release = threading.Event()
    def blocking(raw, **kwargs):
        release.wait(3)
        return {"analysis_status": "PARTIAL", "risk": {"verdict": "UNKNOWN"}, "private_test_value": "PRIVATE_BODY_987"}
    monkeypatch.setattr("app.email.service.analyze", blocking)
    first = first_worker.submit(app, b"private request")
    second = second_worker.submit(app, b"private request 2")
    try:
        assert second_worker.read(first["job_id"], first["token"])["state"] == "RECEIVED"
        with pytest.raises(EmailError, match="EMAIL_QUEUE_FULL"):
            EmailJobs(app).submit(app, b"overflow")
        assert second_worker.read(first["job_id"], "wrong") is None
    finally:
        release.set()
    for _ in range(100):
        row = second_worker.read(first["job_id"], first["token"])
        if row["result"]:
            break
        time.sleep(.01)
    assert row["result"]["private_test_value"] == "PRIVATE_BODY_987"
    ciphertext = first_worker.redis.get("{emailjobs}:result:" + first["job_id"])
    assert b"PRIVATE_BODY_987" not in ciphertext and first["token"].encode() not in ciphertext
    first_worker.redis.set("{emailjobs}:result:" + first["job_id"], b"poisoned result")
    assert second_worker.read(first["job_id"], first["token"]) is None


def test_job_store_failure_releases_capacity(app, monkeypatch):
    from app.email.jobs import EmailJobs
    jobs = EmailJobs()
    def failed(*args):
        raise RuntimeError("provider unavailable")
    monkeypatch.setattr(jobs, "_put", failed)
    with pytest.raises(EmailError, match="EMAIL_JOB_STORE_UNAVAILABLE"):
        jobs.submit(app, b"Hello")
    assert jobs.slots.acquire(False)
    jobs.slots.release()


def test_authentication_passing_phishing_not_whitelisted(app, local_pipeline, monkeypatch, keypair):
    import dkim
    from app.risk.engine import RiskScoringEngine
    from tests.explanation.test_engine import observations
    raw = email("Urgent account verification https://verify-paypal-account.example.net/login").as_bytes()
    signed = dkim.sign(raw, b"s1", b"example.com", keypair[0]) + raw
    parsed = prepared(signed)
    parsed["authentication"] = authenticate(signed, parsed["headers"], dns_lookup=lambda name, **kw: b"v=DMARC1; p=reject" if name.startswith(b"_dmarc") else keypair[1])
    assert parsed["authentication"]["dmarc"]["result"] == "PASS"
    monkeypatch.setattr(local_pipeline, "run", lambda data, artifact, *a, **k: parsed if artifact["mime"] == "--email" else {"status": "UNAVAILABLE"})
    assessment = RiskScoringEngine().calculate(observations())
    assert assessment["verdict"] == "PHISHING"
    monkeypatch.setattr(local_pipeline, "run_linked", lambda *a: {"assessment": assessment})
    with app.app_context():
        result = analyze(signed)
    assert result["risk"]["verdict"] == "PHISHING"
    assert result["risk"]["email_policy"]["authentication_pass_reduces_risk"] is False


def test_dmarc_invalid_policy_and_dns_failure(keypair):
    from app.email.authentication import DNSBudget
    message = email()
    result = authenticate(message.as_bytes(), parse(message.as_bytes())["headers"], dns_lookup=lambda *a, **k: b"v=DMARC1; p=reject; p=none")
    assert result["dmarc"]["result"] == "PERMERROR"
    lookup = DNSBudget()
    assert authenticate(message.as_bytes(), parse(message.as_bytes())["headers"], dns_lookup=lookup)["dmarc"]["result"] in {"NONE", "TEMPERROR"}


def test_poisoned_email_evidence_rejected(app, local_pipeline):
    with app.app_context():
        result = analyze(email().as_bytes())
        result["evidence"][0]["indicator"] = "FAKE_SAFE"
        assert app.extensions["risk_engine"].assess_email(result)["status"] == "ERROR"
        with pytest.raises(ValueError):
            app.extensions["explanation_engine"].explain_email(result)
