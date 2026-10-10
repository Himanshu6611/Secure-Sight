"""Real decoder/OCR/QR tests plus malicious intake and honest missing states."""
import hashlib
import io
import pytest
from PIL import Image, ImageDraw, ImageFont
from app.media.intake import validate, MediaError
from app.media.extract import process
from app.media.provenance import analyze as provenance


def image_bytes(fmt="PNG", size=(128, 128)):
    output = io.BytesIO()
    Image.new("RGB", size, "white").save(output, fmt)
    return output.getvalue()


@pytest.mark.parametrize("fmt,mime", [("PNG", "image/png"), ("JPEG", "image/jpeg"), ("WEBP", "image/webp")])
def test_valid_original_hash(fmt, mime):
    data = image_bytes(fmt)
    assert validate(data, mime)["sha256"] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("fmt", ["PNG", "JPEG", "WEBP"])
def test_mime_mismatch(fmt):
    with pytest.raises(MediaError, match="MAGIC_BYTES_MISMATCH"):
        validate(image_bytes(fmt), "text/html")


@pytest.mark.parametrize("payload", [b"", b"<svg onload='alert(1)'/>", b"GIF89a", b"%PDF-1.7", b"<html>bad</html>"])
def test_unsupported_payload(payload):
    with pytest.raises(MediaError):
        validate(payload, "image/png")


@pytest.mark.parametrize("fmt,mime", [("PNG", "image/png"), ("JPEG", "image/jpeg"), ("WEBP", "image/webp")])
def test_trailing_polyglot(fmt, mime):
    data = image_bytes(fmt) + b"<script>evil()</script>"
    if fmt == "JPEG":
        data += b"\xff\xd9"
    with pytest.raises(MediaError):
        validate(data, mime)


def test_crc_and_size():
    bad = bytearray(image_bytes())
    bad[20] ^= 1
    with pytest.raises(MediaError):
        validate(bytes(bad), "image/png")
    with pytest.raises(MediaError, match="RESOURCE_LIMIT"):
        validate(b"a" * (5 * 1024 * 1024 + 1), "image/png")


@pytest.mark.parametrize("size", [(1, 100), (4097, 2), (4000, 3000)])
def test_decoder_dimensions(size):
    data = image_bytes(size=size)
    with pytest.raises(MediaError, match="RESOURCE_LIMIT"):
        process(data, validate(data, "image/png"))


def test_no_fake_model_or_missing_exif_risk():
    data = image_bytes()
    result = process(data, validate(data, "image/png"))
    assert result["synthetic_media"]["synthetic_probability"] is None
    assert result["synthetic_media"]["analysis_status"] == "INSUFFICIENT_QUALITY"
    assert result["quality"]["status"] == "INSUFFICIENT_QUALITY"
    assert result["forensics"]["confidence"] is None
    assert result["metadata"]["exif_present"] is False
    assert result["provenance"]["status"] == "ABSENT"


def test_licensed_ai_origin_model_runs_and_returns_an_uncalibrated_estimate():
    from app.media.models import ExperimentalAIOriginModel

    image = Image.new("RGB", (256, 256), "white")
    draw = ImageDraw.Draw(image)
    for y in range(0, 256, 8):
        draw.line((0, y, 255, y), fill=(y, 255 - y, (y * 3) % 256), width=4)
    result = ExperimentalAIOriginModel().analyze(image, {"status": "ANALYZED"})

    assert result["analysis_status"] == "EXPERIMENTAL_ESTIMATE"
    assert 0 <= result["model_score"] <= 1
    assert result["calibrated"] is False
    assert result["score_semantics"] == "UNCALIBRATED_MODEL_SCORE"
    assert result["model_sha256"]
    assert result["decision_threshold"] > 0


def test_media_api_returns_model_estimate_without_turning_it_into_threat_verdict(client):
    image = Image.new("RGB", (256, 256), "white")
    draw = ImageDraw.Draw(image)
    for y in range(0, 256, 8):
        draw.line((0, y, 255, y), fill=(y, 255 - y, (y * 3) % 256), width=4)
    output = io.BytesIO()
    image.save(output, "PNG")

    response = client.post(
        "/api/v1/media/analyze",
        data={"file": (io.BytesIO(output.getvalue()), "model-test.png")},
    )
    assert response.status_code == 200
    result = response.get_json()
    assert result["synthetic_media"]["analysis_status"] == "EXPERIMENTAL_ESTIMATE"
    assert 0 <= result["synthetic_media"]["model_score"] <= 1
    assert result["synthetic_media"]["calibrated"] is False
    assert result["investigation"]["checks"]["ai_image_detector"]["status"] == "inconclusive"
    assert result["assessment"]["risk_score"] is None
    assert result["assessment"]["verdict"] == "UNKNOWN"
    assert all(error["code"] != "MODEL_UNAVAILABLE" for error in result["errors"])


def test_real_ocr():
    image = Image.new("RGB", (900, 240), "white")
    font = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)
    ImageDraw.Draw(image).text((20, 50), "PayPal Verify your account", font=font, fill="black")
    output = io.BytesIO(); image.save(output, "PNG")
    data = output.getvalue()
    result = process(data, validate(data, "image/png"))
    assert result["ocr"]["status"] == "ANALYZED"
    assert "PayPal" in result["ocr"]["text"]
    assert result["ocr"]["words"][0]["bbox"]


def test_real_multi_qr():
    import cv2
    image = Image.new("RGB", (700, 340), "white")
    for x, value in ((15, "https://example.com/"), (365, "https://example.org/")):
        encoded = cv2.QRCodeEncoder_create().encode(value)
        qr = Image.fromarray(encoded).resize((280, 280), Image.Resampling.NEAREST)
        image.paste(qr, (x, 25))
    output = io.BytesIO(); image.save(output, "PNG")
    data = output.getvalue(); result = process(data, validate(data, "image/png"))
    assert {item["payload"] for item in result["qr"]["items"]} == {"https://example.com/", "https://example.org/"}
    assert all(item["confidence"] is None for item in result["qr"]["items"])


def test_media_api_worker_and_unknown(client):
    response = client.post("/api/v1/media/analyze", data={"file": (io.BytesIO(image_bytes()), "../../test.png")})
    assert response.status_code == 200
    result = response.get_json()
    assert result["analysis_status"] == "PARTIAL"
    assert result["assessment"]["verdict"] == "UNKNOWN"
    assert result["assessment"]["risk_score"] is None
    assert result["synthid"]["status"] == "NOT_CHECKED"
    assert result["synthid"]["network_request"] is False
    assert result["investigation"]["status"] == "partial"
    assert result["investigation"]["checks"]["ai_image_detector"]["status"] == "inconclusive"
    assert result["investigation"]["checks"]["reverse_image_search"]["network_request"] is False
    assert result["artifact"]["sha256"]
    assert "filename" not in result["artifact"]


@pytest.mark.parametrize("data,mime,code", [(b"<svg/>", "image/svg+xml", "UNSUPPORTED_FORMAT"),
    (image_bytes(), "image/jpeg", "MAGIC_BYTES_MISMATCH"), (b"", "image/png", "INVALID_MEDIA")])
def test_api_errors(client, data, mime, code):
    response = client.post("/api/v1/media/analyze", data={"file": (io.BytesIO(data), "test.png", mime)})
    assert response.status_code >= 400
    assert response.get_json()["error"]["code"] == code
    assert response.get_json()["verdict"] == "UNKNOWN"


def test_api_language_injection(client):
    response = client.post("/api/v1/media/analyze", data={"file": (io.BytesIO(image_bytes()), "test.png"), "language": "eng --config evil"})
    assert response.status_code == 400


def test_pipeline_reuse_dedup_and_email_context(app, monkeypatch):
    from app.media import service
    from werkzeug.datastructures import FileStorage
    data = image_bytes()
    result = process(data, validate(data, "image/png"))
    result["_urls"] = ["https://example.com/", "https://example.com/", "https://other.example/"]
    calls = []
    monkeypatch.setattr(service, "run", lambda *args: result)
    monkeypatch.setattr(service, "run_linked", lambda url, email_context, config: calls.append((url, email_context)) or {})
    with app.app_context():
        output = service.analyze(FileStorage(stream=io.BytesIO(data), content_type="image/png"), email_context={"claimed_brand": "paypal"})
    assert calls == [("https://example.com/", {"claimed_brand": "paypal"})]
    assert output["source"] == "email_attachment"
    assert output["assessment"]["verdict"] == "UNKNOWN"


def test_private_extracted_url_never_scanned(app, monkeypatch):
    from app.media import service
    from werkzeug.datastructures import FileStorage
    data = image_bytes(); result = process(data, validate(data, "image/png"))
    result["_urls"] = ["http://127.0.0.1/private"]
    monkeypatch.setattr(service, "run", lambda *args: result)
    def forbidden(*args, **kwargs):
        pytest.fail("Private URL reached scanner")
    monkeypatch.setattr(service, "run_linked", forbidden)
    with app.app_context():
        output = service.analyze(FileStorage(stream=io.BytesIO(data), content_type="image/png"))
    assert output["correlations"]["errors"] == [{"code": "INVALID_URL"}]


def test_c2pa_unsigned_and_unknown_parse():
    assert provenance(image_bytes("JPEG"), "image/jpeg")["status"] == "ABSENT"
    assert provenance(b"corrupt", "image/jpeg")["status"] in {"ERROR", "ABSENT"}


def test_c2pa_public_claims_exposes_declared_tool_without_other_manifest_data():
    from app.media.provenance import _public_claims
    claims = _public_claims({"active_manifest": "active", "manifests": {"active": {
        "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": [{
            "action": "c2pa.created",
            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
            "softwareAgent": {"name": "Example Generator", "version": "2.4"},
            "privateField": "must not be exposed",
        }]}}]}}})
    assert claims == [{"action": "c2pa.created",
        "digital_source_type": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
        "software_agent": "Example Generator", "software_agent_version": "2.4"}]


def test_real_c2pa_valid_untrusted_and_tampered():
    from media_c2pa_fixture import signed_jpeg
    signed, test_root = signed_jpeg(image_bytes("JPEG"))
    untrusted = provenance(signed, "image/jpeg")
    assert untrusted["status"] == "PRESENT_UNVERIFIED"
    assert untrusted["signature_valid"] is True
    trusted = provenance(signed, "image/jpeg", trusted_anchors=test_root)
    assert trusted["status"] == "VALID" and trusted["trusted"] is True
    assert trusted["claims_available"] is True
    assert trusted["claims"][0]["action"] == "c2pa.created"
    assert trusted["claims"][0]["digital_source_type"].endswith("trainedAlgorithmicMedia")
    assert trusted["claims"][0]["software_agent"] == "SecureSight Test Generator"
    changed = bytearray(signed); changed[-10] ^= 1
    invalid = provenance(bytes(changed), "image/jpeg", trusted_anchors=test_root)
    assert invalid["status"] == "INVALID"
    assert invalid["claims_are_truth"] is False


def test_worker_wall_timeout_and_cleanup(monkeypatch):
    import subprocess
    from app.media import worker
    original = subprocess.Popen
    children = []
    def sleeping(*args, **kwargs):
        child = original([worker.sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(10)"], **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(worker.subprocess, "Popen", sleeping)
    monkeypatch.setattr(worker, "WALL_SECONDS", .25)
    data = image_bytes()
    with pytest.raises(MediaError, match="RESOURCE_LIMIT"):
        worker.run(data, validate(data, "image/png"), "eng")
    assert all(child.poll() is not None for child in children)


def test_worker_output_limit(monkeypatch):
    import subprocess
    from app.media import worker
    original = subprocess.Popen
    def flooding(*args, **kwargs):
        return original([worker.sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.write('x'*300000)"], **kwargs)
    monkeypatch.setattr(worker.subprocess, "Popen", flooding)
    data = image_bytes()
    with pytest.raises(MediaError, match="ANALYSIS_FAILED"):
        worker.run(data, validate(data, "image/png"), "eng")


def test_worker_memory_limit(monkeypatch):
    import subprocess
    from app.media import worker
    if worker.os.name != "nt":
        pytest.skip("Windows job object integration")
    original = subprocess.Popen
    def allocating(*args, **kwargs):
        return original([worker.sys.executable, "-c", "import sys; sys.stdin.buffer.read(); x=bytearray(2*1024**3)"], **kwargs)
    monkeypatch.setattr(worker.subprocess, "Popen", allocating)
    data = image_bytes()
    with pytest.raises(MediaError, match="ANALYSIS_FAILED"):
        worker.run(data, validate(data, "image/png"), "eng")


def test_multilingual_ocr_real():
    image = Image.new("RGB", (950, 250), "white")
    font = ImageFont.truetype("C:/Windows/Fonts/Nirmala.ttc", 44)
    ImageDraw.Draw(image).text((30, 50), "नमस्ते आपका खाता PayPal", font=font, fill="black")
    out = io.BytesIO(); image.save(out, "PNG")
    data = out.getvalue(); result = process(data, validate(data, "image/png"), "eng+hin")
    assert result["ocr"]["status"] == "ANALYZED"
    assert any("\u0900" <= c <= "\u097f" for c in result["ocr"]["text"])


def test_crossmodal_full_shared_scan(app, monkeypatch):
    import cv2
    from werkzeug.datastructures import FileStorage
    from app.media.service import analyze
    from app.media import service
    from app.services import scans
    from tests.explanation.test_engine import observations
    from utils.web_intelligence import analyze_web_intelligence
    context = observations()
    destination = "https://verify-paypal-account.example.net/login"
    monkeypatch.setattr(scans, "analyze_domain_intelligence", lambda url: context["domain_intelligence"])
    monkeypatch.setattr(scans, "analyze_web_intelligence", lambda url: context["web_intelligence"])
    monkeypatch.setattr(service, "run_linked", lambda url, email_context, config: scans.scan_url(url, email_context=email_context))
    image = Image.new("RGB", (900, 450), "white")
    code = cv2.QRCodeEncoder_create().encode(destination)
    image.paste(Image.fromarray(code).resize((350, 350), Image.Resampling.NEAREST), (20, 30))
    font = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 40)
    ImageDraw.Draw(image).text((405, 70), "PayPal account", font=font, fill="black")
    output = io.BytesIO(); image.save(output, "PNG")
    with app.app_context():
        result = analyze(FileStorage(stream=io.BytesIO(output.getvalue()), content_type="image/png"),
                         email_context={"claimed_brand": "paypal", "sender_domain": "mailer.example"})
    assert result["linked_analysis"][0]["assessment"]["assessment_version"]
    assert result["linked_analysis"][0]["brand_intelligence"]["registry_version"] == "9.0.0"
    assert result["brand_analysis"]["observed_brands"] == ["paypal"]
    assert result["correlations"]["brand_destination_observations"][0]["official_domain_relationship"] == "UNMATCHED"
    assert result["assessment"]["media_risk_points"] == 0
    assert any(n["type"] == "EMAIL" for n in result["graph"]["nodes"])
    assert any(n["type"] == "DOMAIN" for n in result["graph"]["nodes"])


def test_progressive_jpeg_and_sensitive_metadata():
    import json
    image = Image.new("RGB", (128, 128), "white")
    exif = Image.Exif()
    exif[271], exif[305], exif[306] = "PRIVATE_DEVICE_123", "Adobe Photoshop", "2026:10:08 01:02:03"
    output = io.BytesIO(); image.save(output, "JPEG", progressive=True, exif=exif)
    data = output.getvalue(); result = process(data, validate(data, "image/jpeg"))
    assert result["metadata"]["camera_present"] is True
    assert result["metadata"]["software_present"] is True
    assert "PRIVATE_DEVICE_123" not in json.dumps(result)
    assert result["synthetic_media"]["synthetic_probability"] is None


def test_xmp_external_entities_not_interpreted():
    from PIL.PngImagePlugin import PngInfo
    metadata = PngInfo()
    metadata.add_text("XML:com.adobe.xmp", '<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///private-secret">]><x>&secret;</x>')
    output = io.BytesIO(); Image.new("RGB", (128, 128), "white").save(output, "PNG", pnginfo=metadata)
    data = output.getvalue(); result = process(data, validate(data, "image/png"))
    assert result["metadata"]["xmp_present"] is True
    assert "private-secret" not in str(result)


def test_animated_media_rejected():
    output = io.BytesIO()
    Image.new("RGB", (128, 128), "white").save(output, "PNG", save_all=True,
        append_images=[Image.new("RGB", (128, 128), "black")], duration=100, loop=0)
    with pytest.raises(MediaError, match="UNSUPPORTED_FORMAT"):
        validate(output.getvalue(), "image/png")


def test_ocr_and_qr_failures_are_explicit(monkeypatch):
    import pytesseract
    import cv2
    def failing(*args, **kwargs):
        raise RuntimeError("native detector failed")
    monkeypatch.setattr(pytesseract, "image_to_data", failing)
    monkeypatch.setattr(cv2, "QRCodeDetector", failing)
    data = image_bytes(); result = process(data, validate(data, "image/png"))
    assert result["ocr"]["status"] == "OCR_FAILED"
    assert result["qr"]["status"] == "QR_DECODE_FAILED"
    assert result["synthetic_media"]["synthetic_probability"] is None


def test_operator_trust_file(tmp_path, monkeypatch):
    from media_c2pa_fixture import signed_jpeg
    signed, root = signed_jpeg(image_bytes("JPEG"))
    path = tmp_path / "operator.pem"
    path.write_text(root)
    monkeypatch.setenv("C2PA_TRUST_ANCHORS_FILE", str(path))
    assert provenance(signed, "image/jpeg")["status"] == "VALID"
    path.write_text("invalid anchors")
    assert provenance(signed, "image/jpeg")["status"] == "ERROR"


def test_linked_failure_propagates(app, monkeypatch):
    from app.media import service
    from werkzeug.datastructures import FileStorage
    data = image_bytes(); result = process(data, validate(data, "image/png"))
    result["_urls"] = ["https://example.com/"]
    monkeypatch.setattr(service, "run", lambda *args: result)
    def failed(*args, **kwargs):
        raise MediaError("RESOURCE_LIMIT", 422)
    monkeypatch.setattr(service, "run_linked", failed)
    with app.app_context():
        output = service.analyze(FileStorage(stream=io.BytesIO(data), content_type="image/png"))
    assert output["assessment"]["verdict"] == "UNKNOWN"
    assert output["assessment"]["risk_score"] is None
    assert {"code": "LINKED_RESOURCE_LIMIT"} in output["errors"]


def test_source_context_uses_shared_scan(app, monkeypatch):
    from app.media import service
    from werkzeug.datastructures import FileStorage
    data = image_bytes(); result = process(data, validate(data, "image/png"))
    calls = []
    monkeypatch.setattr(service, "run", lambda *args: result)
    monkeypatch.setattr(service, "run_linked", lambda url, *args: calls.append(url) or {})
    with app.app_context():
        output = service.analyze(FileStorage(stream=io.BytesIO(data), content_type="image/png"), source_url="https://example.com/image")
    assert calls == ["https://example.com/image"]
    assert output["source"] == "website_attachment"
    assert output["correlations"]["source_claim_verified"] is False


def test_invalid_source_api_failure(client):
    response = client.post("/api/v1/media/analyze", data={"file": (io.BytesIO(image_bytes()), "test.png"), "source_url": "http://127.0.0.1/private"})
    assert response.status_code == 400


def test_worker_cpu_limit(monkeypatch):
    import subprocess
    from app.media import worker
    if worker.os.name != "nt":
        pytest.skip("Windows job object CPU integration")
    original = subprocess.Popen
    children = []
    def burning(*args, **kwargs):
        child = original([worker.sys.executable, "-c", "import sys; sys.stdin.buffer.read(); exec('while True: pass')"], **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(worker.subprocess, "Popen", burning)
    monkeypatch.setattr(worker, "CPU_SECONDS", .25)
    data = image_bytes()
    with pytest.raises(MediaError, match="ANALYSIS_FAILED"):
        worker.run(data, validate(data, "image/png"), "eng")
    assert all(child.poll() is not None for child in children)


@pytest.mark.parametrize("verdict,expected_class", [("PHISHING", "verdict-danger"), ("SUSPICIOUS", "verdict-unknown")])
def test_media_destination_warning_never_green(client, monkeypatch, verdict, expected_class):
    from app.media import service
    from app.risk.engine import RiskScoringEngine
    from tests.explanation.test_engine import observations
    data = image_bytes(); result = process(data, validate(data, "image/png"))
    result["_urls"] = ["https://example.com/"]
    context = observations()
    linked = RiskScoringEngine().calculate(context)
    linked["verdict"] = verdict
    monkeypatch.setattr(service, "run", lambda *args: result)
    monkeypatch.setattr(service, "run_linked", lambda *args: {"assessment": linked, "verdict": verdict,
        "risk_score": linked["risk_score"], "url": "https://example.com/", "explanation": {"summary": "Fixture destination evidence."}})
    response = client.post("/api/v1/media/analyze", data={"file": (io.BytesIO(data), "test.png")}, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.json["assessment"]["verdict"] == verdict
