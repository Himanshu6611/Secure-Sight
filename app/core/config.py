"""Validated environment configuration; no persistent development secrets."""
import os
import secrets
from urllib.parse import urlsplit
from limits import parse_many
from .secrets import runtime_secret


def configure(app, overrides=None):
    app.config.from_mapping(
        APP_ENV=os.getenv("APP_ENV", "development"),
        SECRET_KEY=runtime_secret("FLASK_SECRET_KEY") or None,
        DASHBOARD_ENCRYPTION_KEY=runtime_secret("DASHBOARD_ENCRYPTION_KEY"),
        SITE_URL=os.getenv("SITE_URL", "http://localhost:5000").rstrip("/"),
        ALLOWED_ORIGINS=[x.strip() for x in os.getenv("ALLOWED_ORIGINS", "").split(",") if x.strip()],
        TRUSTED_HOSTS=[x.strip() for x in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1,[::1]").split(",") if x.strip()],
        LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO"),
        MAX_CONTENT_LENGTH=6 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=128 * 1024,
        MAX_FORM_PARTS=10,
        MAX_URL_LENGTH=2048,
        MAX_EMAIL_LENGTH=100_000,
        MAX_JSON_BYTES=8192,
        MAX_CONCURRENT_SCANS=int(os.getenv("MAX_CONCURRENT_SCANS", "2")),
        SCAN_RATE_LIMIT=os.getenv("SCAN_RATE_LIMIT", "20 per minute"),
        ACTOR_SCAN_RATE_LIMIT=os.getenv("ACTOR_SCAN_RATE_LIMIT", "10 per minute"),
        RATELIMIT_STORAGE_URI=runtime_secret("RATELIMIT_STORAGE_URI") or "memory://",
        RATELIMIT_HEADERS_ENABLED=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if overrides:
        app.config.update(overrides)
    c = app.config
    if c["APP_ENV"] not in {"development", "testing", "production"}:
        raise ValueError("APP_ENV must be development, testing or production.")
    production = c["APP_ENV"] == "production"
    secret = c["SECRET_KEY"]
    if production and (not secret or len(secret) < 32 or "change-me" in secret):
        raise ValueError("FLASK_SECRET_KEY must be a strong secret of at least 32 characters in production.")
    c["SECRET_KEY"] = secret or secrets.token_hex(32)
    c["SESSION_COOKIE_SECURE"] = production
    for name in ("MAX_CONTENT_LENGTH", "MAX_FORM_MEMORY_SIZE", "MAX_FORM_PARTS", "MAX_URL_LENGTH", "MAX_EMAIL_LENGTH", "MAX_JSON_BYTES", "MAX_CONCURRENT_SCANS"):
        if type(c[name]) is not int or c[name] <= 0:
            raise ValueError(f"{name} must be a positive integer.")
    if c["LOG_LEVEL"] not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("LOG_LEVEL is invalid.")
    for name in ("SCAN_RATE_LIMIT", "ACTOR_SCAN_RATE_LIMIT"):
        try:
            rules = parse_many(c[name])
            if not rules or any(rule.amount <= 0 for rule in rules):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError(f"{name} must be a positive rate, for example '20 per minute'.") from None
    for value in [c["SITE_URL"], *c["ALLOWED_ORIGINS"]]:
        try:
            p = urlsplit(value)
            valid = (p.scheme in {"http", "https"} and p.hostname and not p.username
                     and not p.password and p.path in {"", "/"} and not p.query and not p.fragment
                     and not any(ch.isspace() or ch in '<>"\\' for ch in value))
            p.port
        except ValueError:
            valid = False
        if not valid or (production and p.scheme != "https"):
            raise ValueError("SITE_URL and ALLOWED_ORIGINS must be explicit origins (HTTPS in production).")
    if not c["TRUSTED_HOSTS"] or any("*" in h or "/" in h for h in c["TRUSTED_HOSTS"]):
        raise ValueError("TRUSTED_HOSTS must contain explicit hostnames.")
    if production and not c["RATELIMIT_STORAGE_URI"].startswith(("redis://", "rediss://")):
        raise ValueError("RATELIMIT_STORAGE_URI must use shared Redis storage in production.")
