import io
import zipfile

import pytest

from app.email.documents import extract
from app.email.parser import EmailError


def test_xml_extracts_text_and_links_without_resolving_entities():
    text = extract(b'<message><subject>Urgent</subject><body>Visit https://example.test</body></message>', "xml")
    assert "Urgent" in text and "https://example.test" in text
    with pytest.raises(EmailError, match="DOCUMENT_PARSE_FAILED"):
        extract(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', "xml")


def test_docx_extracts_only_document_text():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types xmlns='urn:test'/>")
        archive.writestr("word/document.xml", "<document xmlns:w='urn:w'><w:t>Review https://example.test</w:t></document>")
    assert "Review https://example.test" in extract(stream.getvalue(), "docx")


def test_pdf_extraction_is_bounded_and_requires_pdf_signature(monkeypatch):
    class Page:
        def extract_text(self):
            return "Email text"

    class Reader:
        is_encrypted = False
        pages = [Page()]

    monkeypatch.setattr("app.email.documents.PdfReader", lambda *_args, **_kwargs: Reader())
    assert extract(b"%PDF-1.7\n", "pdf") == "Email text"
    with pytest.raises(EmailError, match="DOCUMENT_TYPE_MISMATCH"):
        extract(b"not a pdf", "pdf")


def test_document_extraction_runs_in_isolated_worker():
    from app.media.worker import run

    result = run(b"<message><body>https://example.test</body></message>",
                 {"mime": "--email-document"}, "xml", wall_seconds=8)
    assert result == {"text": "https://example.test", "format": "xml"}


def test_email_api_accepts_document_exports_and_preserves_auth_limits(client, app, monkeypatch):
    from app.email.jobs import get_jobs

    seen = {}

    def fake_extract(raw, artifact, document_format, **_kwargs):
        seen["worker"] = (artifact["mime"], document_format, raw)
        return {"text": "Forward this link https://example.test", "format": document_format}

    def fake_submit(_application, raw):
        seen["message"] = raw
        return {"job_id": "a" * 32, "token": "test-token"}

    monkeypatch.setattr("app.media.worker.run", fake_extract)
    with app.app_context():
        jobs = get_jobs()
    monkeypatch.setattr(jobs, "submit", fake_submit)
    response = client.post("/api/v1/email/analyze", data={
        "file": (io.BytesIO(b"%PDF-1.7 fake"), "forwarded.pdf", "application/pdf")
    }, content_type="multipart/form-data")

    assert response.status_code == 202
    assert seen["worker"][:2] == ("--email-document", "pdf")
    assert b"Forward this link https://example.test" in seen["message"]
    assert b"X-SecureSight-Input-Format: pdf" in seen["message"]


def test_email_api_rejects_unsupported_document_extensions(client):
    response = client.post("/api/v1/email/analyze", data={
        "file": (io.BytesIO(b"hello"), "message.doc", "application/msword")
    }, content_type="multipart/form-data")
    assert response.status_code == 415
    assert response.json["error"]["code"] == "UNSUPPORTED_EMAIL_FORMAT"


def test_media_investigate_reports_provider_limits_and_explicit_opt_in(client, monkeypatch):
    from PIL import Image

    output = io.BytesIO()
    Image.new("RGB", (64, 64), "white").save(output, "PNG")
    observed = {}

    def fake_analyze(_file, language, **options):
        observed["options"] = options
        from app.media.report import build
        result = {"created_at": "2026-10-09T00:00:00+00:00", "retention": "request_only",
            "provenance": {"status": "ABSENT", "signature_valid": None, "trusted": None},
            "metadata": {"status": "ANALYZED", "exif_present": False},
            "forensics": {"status": "ANALYZED"}, "synthetic_media": {"analysis_status": "MODEL_UNAVAILABLE"},
            "synthid": {"status": "NOT_CHECKED", "provider": "GOOGLE_SYNTHID_DETECTOR"}}
        result["investigation"] = build(result, **options)
        return result

    monkeypatch.setattr("app.media.service.analyze", fake_analyze)
    response = client.post("/api/v1/media/investigate", data={
        "image": (io.BytesIO(output.getvalue()), "sample.png", "image/png"),
        "checks": "c2pa,reverse_image_search,content_safety",
        "reverse_search": "true", "content_safety": "true",
    }, content_type="multipart/form-data")
    assert response.status_code == 200
    report = response.json["investigation"]
    assert report["status"] == "partial"
    assert report["checks"]["reverse_image_search"]["status"] == "not_available"
    assert report["checks"]["reverse_image_search"]["network_request"] is False
    assert report["checks"]["content_safety"]["status"] == "not_available"
    assert "reverse_image_search" in report["coverage"]["requested"]
    assert observed["options"]["reverse_search"] is True


def test_media_investigate_rejects_unknown_check(client, monkeypatch):
    monkeypatch.setattr("app.media.service.analyze", lambda *_args, **_kwargs: pytest.fail("must reject options before analysis"))
    response = client.post("/api/v1/media/investigate", data={
        "image": (io.BytesIO(b"not decoded due to invalid check"), "sample.png", "image/png"),
        "checks": "face_recognition",
    }, content_type="multipart/form-data")
    assert response.status_code == 400
    assert response.json["error"]["code"] == "INVALID_OPTIONS"
