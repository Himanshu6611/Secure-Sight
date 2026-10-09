"""Bounded local adversarial cases: no external sockets or executable payloads."""
import random
from unittest.mock import Mock
import pytest
from app.email.parser import parse, EmailError
from app.media.intake import validate as validate_media, MediaError
from app.security.urls import validate_url, InvalidURL
from app.security import outbound
from tests.test_phase12_dashboard import accounts, authenticate, saved, url_result


@pytest.mark.parametrize("target", [
    "http://127.1/", "http://2130706433/", "http://0177.0.0.1/",
    "http://0x7f000001/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "http://[64:ff9b::7f00:1]/", "http://169.254.169.254/",
    "https://public.example@127.0.0.1/", "https://example.com\\@127.0.0.1/",
    "https://example.com:8080/", "file:///test", "javascript:alert(1)",
    "https://example.com/%0d%0aHeader:x", "https://example.com/%zz",
])
def test_ambiguous_or_restricted_targets(target):
    with pytest.raises(InvalidURL):
        validate_url(target)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fc00::1", "::ffff:8.8.8.8"])
def test_mixed_answers_block_before_pool(monkeypatch, address):
    socket = Mock(side_effect=AssertionError("No socket may be opened"))
    monkeypatch.setattr(outbound.urllib3, "HTTPSConnectionPool", socket)
    with pytest.raises(InvalidURL):
        outbound.pinned_pool("https://example.com/", ["8.8.8.8", address])
    socket.assert_not_called()


@pytest.mark.parametrize("depth,kind", [(10, "multipart"), (1200, "multipart"), (1200, "message")])
def test_nested_mime_is_bounded_before_tree(depth, kind, monkeypatch):
    raw = b"Content-Type: text/plain\r\n\r\nsafe"
    for i in range(depth):
        if kind == "message":
            raw = b"Content-Type: message/rfc822\r\n\r\n" + raw
        else:
            boundary = str(i).encode()
            raw = b"Content-Type: multipart/mixed; boundary=" + boundary + b"\r\n\r\n--" + boundary + b"\r\n" + raw + b"\r\n--" + boundary + b"--\r\n"
    if depth > 32:
        constructor = Mock(side_effect=AssertionError("Preflight must reject before parsing"))
        monkeypatch.setattr("app.email.parser.BytesParser", constructor)
    with pytest.raises(EmailError) as error:
        parse(raw)
    assert error.value.code == "MIME_RESOURCE_LIMIT" and error.value.status == 413


def test_bounded_parser_mutations():
    generator = random.Random(20261009)
    prefixes = [b"From: safe@example.com\r\n\r\n", b"Content-Type: text/plain; charset=bad-charset\r\n\r\n", b"Content-Type: multipart/mixed; boundary=x\r\n\r\n", b"Content-Transfer-Encoding: base64\r\n\r\n"]
    for i in range(150):
        raw = prefixes[i % len(prefixes)] + generator.randbytes(generator.randrange(1, 512))
        try:
            parsed = parse(raw)
            assert parsed["raw_retention"] == "REQUEST_ONLY" and parsed["parts"] <= 32
        except EmailError as error:
            assert error.status in {400, 413}


def test_bounded_media_mutations():
    generator = random.Random(15)
    for i in range(150):
        data = [b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF89a", b"<svg><script>harmless</script>"][i % 4] + generator.randbytes(128)
        with pytest.raises(MediaError):
            validate_media(data, "image/png")


@pytest.mark.parametrize("value", ["https://EXAMPLE.com./a/../b?q=%252f#safe", "https://例え.jp/", "https://example.com/?next=http%3A%2F%2F127.0.0.1"])
def test_normalized_security_policy_is_idempotent(value):
    normalized = validate_url(value)
    assert validate_url(normalized) == normalized


@pytest.mark.parametrize("suffix", ["/graph", "/timeline", "/evidence", "/export?format=json"])
def test_foreign_export_and_evidence_are_not_visible(client, accounts, saved, suffix):
    authenticate(client, accounts["other"])
    response = client.get("/api/v1/investigations/" + saved + suffix)
    assert response.status_code == 404 and response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("field", ["risk", "verdict", "confidence", "role", "tenant", "evidence"])
def test_case_cannot_overwrite_backend_scoring(client, accounts, saved, field):
    headers = authenticate(client, accounts["analyst"])
    before = client.get("/api/v1/investigations/" + saved).json["summary"]
    response = client.post("/api/v1/cases", json={"title": "Harmless adversarial fixture", "investigation_ids": [saved], field: "forged"}, headers=headers)
    assert response.status_code == 400
    assert client.get("/api/v1/investigations/" + saved).json["summary"] == before
