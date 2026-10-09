"""Streamlit Community Cloud entry point for SecureSight's shared Flask scanners.

The Flask test client is used as an in-process adapter, not exposed as a network
server. This keeps validation, rate limits, worker isolation and response
contracts on the existing API paths.
"""
from __future__ import annotations

import io
import os
import time
from typing import Any

import streamlit as st

MAX_UPLOAD_BYTES = 6 * 1024 * 1024
EMAIL_WAIT_SECONDS = 100


def _secret(name: str) -> str:
    """Read a deployment value without logging or rendering its value."""
    value = os.getenv(name)
    if value:
        return value.strip()
    try:
        value = st.secrets.get(name, "")
    except Exception:
        value = ""
    return str(value).strip()


def deployment_config() -> tuple[dict[str, Any] | None, list[str]]:
    """Build strict production settings; never silently downgrade public security."""
    secret_key = _secret("FLASK_SECRET_KEY")
    redis_uri = _secret("RATELIMIT_STORAGE_URI")
    site_url = _secret("SITE_URL")
    missing = [name for name, value in (
        ("FLASK_SECRET_KEY", secret_key),
        ("RATELIMIT_STORAGE_URI", redis_uri),
        ("SITE_URL", site_url),
    ) if not value]
    if missing:
        return None, missing
    if (len(secret_key) < 32 or len(set(secret_key)) < 8
            or any(marker in secret_key.casefold() for marker in ("change-me", "replace_with", "your_password"))):
        return None, ["FLASK_SECRET_KEY must be a generated value with at least 32 characters"]
    if not redis_uri.startswith("rediss://"):
        return None, ["RATELIMIT_STORAGE_URI must be a TLS-protected rediss:// URL"]
    if not site_url.startswith("https://") or "your_app" in site_url.casefold():
        return None, ["SITE_URL must be the app's actual HTTPS origin"]

    config: dict[str, Any] = {
        "APP_ENV": "production",
        "SECRET_KEY": secret_key,
        "SITE_URL": site_url.rstrip("/"),
        "RATELIMIT_STORAGE_URI": redis_uri,
        "TRUSTED_HOSTS": ["localhost", "127.0.0.1", "[::1]"],
        # The Streamlit UI is same-origin and does not expose cross-origin API calls.
        "ALLOWED_ORIGINS": [],
        # Private investigation accounts need a separately provisioned durable store;
        # this public, single-process UI does not persist dashboard data.
        "DASHBOARD_DB_PATH": "",
        "DASHBOARD_ENCRYPTION_KEY": "",
        "MAX_CONTENT_LENGTH": MAX_UPLOAD_BYTES,
    }
    return config, []


@st.cache_resource(show_spinner=False)
def _flask_app():
    config, errors = deployment_config()
    if errors or config is None:
        raise RuntimeError("Secure deployment settings are incomplete")
    from app import create_app

    return create_app(config)


def _verdict(result: dict[str, Any], family: str) -> None:
    if family == "url":
        verdict = result.get("verdict", "UNKNOWN")
        risk = result.get("risk_score")
        probability = result.get("ml_probability")
        coverage = result.get("evidence_coverage")
        detail = result.get("decision", "Analysis incomplete")
    elif family == "email":
        assessment = result.get("risk", {})
        verdict = assessment.get("verdict", "UNKNOWN")
        risk = assessment.get("risk_score")
        probability = None
        coverage = assessment.get("evidence_coverage")
        detail = assessment.get("decision", verdict.replace("_", " ").title())
    else:
        assessment = result.get("assessment", {})
        verdict = assessment.get("verdict", "UNKNOWN")
        risk = assessment.get("risk_score")
        probability = None
        coverage = assessment.get("evidence_coverage")
        detail = assessment.get("decision", verdict.replace("_", " ").title())

    if verdict == "PHISHING":
        st.error(f"{detail} — do not open links or share information.")
    elif verdict == "SUSPICIOUS":
        st.warning(f"{detail} — verify the source before interacting.")
    elif verdict == "LEGITIMATE":
        st.success(f"{detail} — no strong phishing indicators were observed.")
    else:
        st.info(f"{detail} — checks were incomplete; treat this result cautiously.")

    left, middle, right = st.columns(3)
    left.metric("Observed risk score", "Unavailable" if risk is None else f"{risk}/100")
    middle.metric("Model estimate", "Unavailable" if probability is None else f"{probability:.1%}")
    right.metric("Evidence coverage", "Unavailable" if coverage is None else f"{coverage:.0%}")
    st.caption("Risk score and model estimate are different measures. Neither guarantees that content is safe.")


def _show_result(result: dict[str, Any], family: str) -> None:
    _verdict(result, family)
    with st.expander("Evidence and technical details"):
        st.json(result, expanded=False)


def _request_url(value: str) -> dict[str, Any]:
    app = _flask_app()
    with app.test_client() as client:
        response = client.post("/api/v1/scan", json={"url": value})
        data = response.get_json(silent=True)
    if response.status_code >= 400 or not isinstance(data, dict):
        raise RuntimeError("The URL scan could not be completed. Check the address and try again.")
    return data


def _request_image(filename: str, content: bytes) -> dict[str, Any]:
    app = _flask_app()
    with app.test_client() as client:
        response = client.post(
            "/api/v1/media/analyze",
            data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )
        data = response.get_json(silent=True)
    if response.status_code >= 400 or not isinstance(data, dict):
        raise RuntimeError("The image scan could not be completed. Use a PNG, JPEG or WebP under 6 MB.")
    return data


def _request_email(filename: str, content: bytes) -> dict[str, Any]:
    app = _flask_app()
    with app.test_client() as client:
        response = client.post(
            "/api/v1/email/analyze",
            data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )
        job = response.get_json(silent=True)
        if response.status_code != 202 or not isinstance(job, dict):
            raise RuntimeError("The email could not be queued. Check the file type and size, then retry.")
        deadline = time.monotonic() + EMAIL_WAIT_SECONDS
        while time.monotonic() < deadline:
            poll = client.get(
                job["poll_url"],
                headers={"Authorization": "Bearer " + job["token"]},
            )
            state = poll.get_json(silent=True)
            if poll.status_code != 200 or not isinstance(state, dict):
                raise RuntimeError("The temporary email result is unavailable. Please submit it again.")
            if state.get("state") in {"PARTIAL", "ANALYZED", "FAILED"}:
                result = state.get("result")
                if isinstance(result, dict):
                    return result
                raise RuntimeError("Email analysis ended without a result.")
            time.sleep(0.4)
    raise RuntimeError("Email analysis exceeded its 100-second limit. Try a smaller file.")


def main() -> None:
    st.set_page_config(page_title="SecureSight", page_icon="🛡️", layout="wide")
    st.title("SecureSight")
    st.write("Check a link, email file, or image for observable security signals.")
    st.caption("Results are decision support. A clean result is not proof that content is safe.")

    config, errors = deployment_config()
    if errors or config is None:
        st.error("SecureSight is not configured for public use yet.")
        st.write("Add the required values in Streamlit Community Cloud → App settings → Secrets.")
        st.code("FLASK_SECRET_KEY = \"<generated 32+ character secret>\"\nRATELIMIT_STORAGE_URI = \"rediss://...\"\nSITE_URL = \"https://<your-app>.streamlit.app\"", language="toml")
        st.caption("Never paste secrets into chat or commit them to GitHub. Configure a TLS Redis service before deployment.")
        st.stop()

    url_tab, email_tab, image_tab = st.tabs(["Website link", "Email file", "Image"])
    with url_tab:
        with st.form("url_scan"):
            url = st.text_input("Website address", placeholder="https://example.com", max_chars=2048)
            scan_url = st.form_submit_button("Check link", type="primary")
        if scan_url:
            if not url.strip():
                st.warning("Enter a website address first.")
            else:
                try:
                    with st.spinner("Checking the address and available website signals…"):
                        result = _request_url(url.strip())
                    _show_result(result, "url")
                except Exception as exc:
                    st.error(str(exc) if isinstance(exc, RuntimeError) else "The scan failed safely. Please retry later.")

    with email_tab:
        st.write("Accepted formats: EML, PDF, DOCX and XML. Up to 2 MB per file.")
        email_file = st.file_uploader("Choose an email or email export", type=["eml", "pdf", "docx", "xml"], key="email_file")
        if st.button("Check email", type="primary", key="check_email"):
            if email_file is None:
                st.warning("Choose a file first.")
            elif email_file.size > 2 * 1024 * 1024:
                st.error("The email file must be 2 MB or smaller.")
            else:
                try:
                    with st.spinner("Inspecting the message, attachments and links…"):
                        result = _request_email(email_file.name, email_file.getvalue())
                    _show_result(result, "email")
                except Exception as exc:
                    st.error(str(exc) if isinstance(exc, RuntimeError) else "Email analysis failed safely. Please retry later.")

    with image_tab:
        st.write("Accepted formats: PNG, JPEG and WebP. Up to 6 MB per image.")
        image_file = st.file_uploader("Choose an image", type=["png", "jpg", "jpeg", "webp"], key="image_file")
        if st.button("Check image", type="primary", key="check_image"):
            if image_file is None:
                st.warning("Choose an image first.")
            elif image_file.size > MAX_UPLOAD_BYTES:
                st.error("The image must be 6 MB or smaller.")
            else:
                try:
                    with st.spinner("Inspecting image metadata, provenance, text and available indicators…"):
                        result = _request_image(image_file.name, image_file.getvalue())
                    _show_result(result, "image")
                    st.caption("AI-image/deepfake origin cannot be reliably confirmed without a validated detector or trusted provenance signal.")
                except Exception as exc:
                    st.error(str(exc) if isinstance(exc, RuntimeError) else "Image analysis failed safely. Please retry later.")

    st.divider()
    st.caption("Uploads are handled in memory and temporary worker storage for analysis. Do not submit confidential files to a public demo.")


if __name__ == "__main__":
    main()
