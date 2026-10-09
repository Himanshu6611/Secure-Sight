import io
from unittest.mock import Mock
import pytest
from PIL import Image
from app.security import outbound
from app.security.urls import InvalidURL
from utils import reputation


def test_image_real_pipeline(client):
    image = Image.new("RGB", (64, 64), (100, 140, 180))
    data = io.BytesIO()
    image.save(data, format="PNG")
    data.seek(0)
    response = client.post("/api/v1/media/analyze", data={"file": (data, "sample.png")}, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.json["assessment"]["verdict"] == "UNKNOWN"


@pytest.mark.parametrize("payload,name", [(b"not an image", "test.png"), (b"<svg onload=alert(1)>", "test.svg")])
def test_invalid_image(client, payload, name):
    response = client.post("/api/v1/media/analyze", data={"file": (io.BytesIO(payload), name)}, content_type="multipart/form-data")
    assert response.status_code in {400, 415}


def test_image_encoding_and_dimensions(client):
    for format, size in [("GIF", (64, 64)), ("PNG", (4097, 2)), ("PNG", (1, 1))]:
        data = io.BytesIO()
        Image.new("RGB", size).save(data, format=format)
        data.seek(0)
        response = client.post("/api/v1/media/analyze", data={"file": (data, "test.png")}, content_type="multipart/form-data")
        assert response.status_code in {400, 415}


def test_whois_rejects_private_referral(monkeypatch):
    calls = []
    def resolve(host, timeout):
        calls.append(host)
        return ["8.8.8.8"]
    monkeypatch.setattr(outbound, "resolve_public", resolve)
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    connection.recv.side_effect = [b"refer: 127.0.0.1\r\n", b""]
    factory = Mock(return_value=connection)
    monkeypatch.setattr(outbound.socket, "create_connection", factory)
    with pytest.raises(InvalidURL):
        outbound.whois_text("example.com")
    factory.assert_called_once()
    assert calls == ["whois.iana.org"]


def test_whois_response_limit(monkeypatch):
    monkeypatch.setattr(outbound, "resolve_public", lambda *a: ["8.8.8.8"])
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    replies = iter([b"whois: whois.example.com\r\n", b""])
    connection.recv.side_effect = lambda size: next(replies, b"x" * size)
    monkeypatch.setattr(outbound.socket, "create_connection", Mock(return_value=connection))
    assert len(outbound.whois_text("example.com")) == 65536
    assert [call.args[0] for call in connection.sendall.call_args_list] == [b"com\r\n", b"example.com\r\n"]


def test_whois_does_not_use_tld_creation_date(monkeypatch):
    monkeypatch.setattr(outbound, "resolve_public", lambda *a: ["8.8.8.8"])
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    connection.recv.side_effect = [b"created: 1985-01-01\r\n", b""]
    monkeypatch.setattr(outbound.socket, "create_connection", Mock(return_value=connection))
    assert outbound.whois_text("example.com") == ""


def test_risk_formula_and_reputation_snapshot(client, monkeypatch):
    result = client.post("/api/v1/scan", json={"url": "https://example.com"}).json
    assert result["decision"] == "Analysis incomplete"
    assert "REPUTATION_UNCONFIRMED" in result["warnings"]
    assert result["risk_score_kind"].endswith("not a safety probability")
    features = {"token_hits": 0, "has_ip": 0, "https": 1, "entropy": 0}
    assert reputation.compute_risk_score("https://example.com", features, (3650, True, 0)) == 0
    assert reputation.compute_risk_score("https://example.com", features, (0, False, 1)) == 75


def test_training_dependency_imports():
    import scripts.train_ensemble
    import scripts.train_email_model
