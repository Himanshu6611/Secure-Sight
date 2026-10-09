import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from app import create_app

@pytest.fixture
def app():
    app = create_app({
        "TESTING": True,
        "APP_ENV": "testing",
        "SITE_URL": "http://localhost:5000",
        "TRUSTED_HOSTS": ["localhost"],
        "ALLOWED_ORIGINS": [],
        "RATELIMIT_STORAGE_URI": "memory://",
    })
    yield app

@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def offline_network(monkeypatch):
    """All regression/security tests use deterministic local reputation data."""
    from app.security.circuit import PROVIDER_CIRCUIT
    PROVIDER_CIRCUIT.clear()  # Independent test cases must not share provider failure state.
    import socket
    from utils import reputation
    monkeypatch.setattr(reputation, "_domain_age_in_days", lambda domain: 3650)
    monkeypatch.setattr(reputation, "_has_valid_ssl", lambda url: True)
    def blocked(*args, **kwargs):
        raise AssertionError("Tests must not contact external systems")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    import dns.resolver
    def no_dns(*args, **kwargs):
        raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr(dns.resolver, "resolve", no_dns)

