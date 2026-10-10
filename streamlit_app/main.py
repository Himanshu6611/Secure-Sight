"""Streamlit Community Cloud entry point for SecureSight's shared Flask scanners.

The Flask test client is used as an in-process adapter, not exposed as a network
server. This keeps validation, rate limits, worker isolation and response
contracts on the existing API paths.
"""
from __future__ import annotations

import io
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any

import streamlit as st

# Community Cloud runs this file from its subdirectory. Ensure shared project
# packages (app/, ml/, utils/) are importable from the repository root.
REPOSITORY_ROOT = str(Path(__file__).resolve().parents[1])
# Keep project packages ahead of any similarly named packages installed by
# Community Cloud (notably the project's local ``ml`` package).
if REPOSITORY_ROOT in sys.path:
    sys.path.remove(REPOSITORY_ROOT)
sys.path.insert(0, REPOSITORY_ROOT)

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
    right.metric("Evidence coverage", _coverage_label(coverage))
    st.caption("Risk score and model estimate are different measures. Neither guarantees that content is safe.")


def _coverage_label(value: Any) -> str:
    if not isinstance(value, (int, float)) or not 0 <= value <= 100:
        return "Unavailable"
    # The API contract expresses coverage in percentage points (0..100).
    # Treating values above 1 as fractions caused 65 to render as 6500%.
    return f"{value:.0f}%"


def _domain_age(registration: dict[str, Any]) -> str:
    days = registration.get("domain_age_days")
    if isinstance(days, (int, float)) and days >= 0:
        years = registration.get("domain_age_years")
        if not isinstance(years, (int, float)):
            years = days / 365.2425
        return f"{days:,.0f} days · {years:.1f} years"
    return "Unavailable from registration data"


def _url_verdict_text(verdict: str) -> tuple[str, str]:
    if verdict == "PHISHING":
        return "Unsafe — threat indicators found", "error"
    if verdict == "SUSPICIOUS":
        return "Suspicious — verify before opening", "warning"
    if verdict in {"LEGITIMATE", "LOW_RISK"}:
        return "No strong threat indicators found", "success"
    return "Needs review — some checks are incomplete", "info"


def _model_status_text(status: str, failure_reason: str | None = None) -> str:
    explanations = {
        "MODEL_NOT_FOUND": "The URL model artifact is missing from this deployment.",
        "MODEL_VERSION_MISMATCH": "The URL model does not match this deployment's supported runtime or schema.",
        "MODEL_LOAD_FAILED": "The URL model failed its integrity or loading checks.",
        "FEATURE_SCHEMA_MISMATCH": "The URL model feature schema is incompatible with this scanner.",
    }
    message = explanations.get(status, "The URL model could not produce an estimate for this scan.")
    if status == "MODEL_LOAD_FAILED" and failure_reason:
        if failure_reason.startswith("CHECKSUM_MISMATCH:"):
            message = "The URL model artifact failed its integrity check."
        elif failure_reason.startswith("CHECKSUM_METADATA_MISSING:"):
            message = "The URL model is missing required integrity metadata."
        elif failure_reason.startswith("MODEL_DESERIALIZATION_ERROR:"):
            message = "The URL model could not be opened by the deployed Python runtime."
        elif failure_reason == "MODEL_THRESHOLD_INVALID":
            message = "The URL model's saved decision threshold is invalid."
    return message


def _show_url_result(result: dict[str, Any]) -> None:
    verdict = str(result.get("verdict", "UNKNOWN")).upper()
    label, level = _url_verdict_text(verdict)
    message = f"**{label}**"
    if level == "error":
        st.error(message)
    elif level == "warning":
        st.warning(message)
    elif level == "success":
        st.success(message)
    else:
        st.info(message)

    risk = result.get("risk_score")
    probability = result.get("ml_probability")
    coverage = result.get("evidence_coverage")
    completeness = result.get("analysis_completeness")
    confidence = result.get("confidence")
    risk_label = f"{risk:.2f}/100" if isinstance(risk, (int, float)) else "Unavailable"
    model_label = f"{probability:.1%}" if isinstance(probability, (int, float)) else "Unavailable"
    first, second, third, fourth = st.columns(4)
    first.metric("Observed risk score", risk_label)
    second.metric("ML phishing estimate", model_label)
    third.metric("Evidence coverage", _coverage_label(coverage))
    fourth.metric("Analysis completeness", _coverage_label(completeness))
    st.caption("A score is evidence for review, not a guarantee. A clean result does not prove a site is safe.")

    target = result.get("analysis_target") or result.get("url")
    if isinstance(target, str):
        st.markdown("**Analyzed website**")
        st.code(target, language=None)

    domain = result.get("domain_intelligence") or {}
    components = domain.get("domain_components") or {}
    registration = domain.get("registration") or {}
    tls = domain.get("tls") or {}
    dns = domain.get("dns") or {}
    reputation = domain.get("reputation") or {}
    web = result.get("web_intelligence") or {}
    features = web.get("combined_web_features") or {}
    behavior = web.get("behavior_intelligence") or {}
    dynamic = behavior.get("dynamic_analysis") or {}
    fetch = web.get("fetch_summary") or {}

    st.subheader("Website and domain details")
    domain_col, registration_col = st.columns(2)
    with domain_col:
        st.markdown("**Domain**")
        st.write(components.get("registrable_domain") or "Unavailable")
        st.markdown("**Domain age (WHOIS/RDAP)**")
        st.write(_domain_age(registration))
        created = registration.get("creation_date")
        st.markdown("**Registration date**")
        st.write(created[:10] if isinstance(created, str) and created else "Unavailable")
        st.markdown("**Registration data source**")
        st.write(registration.get("source") or "Unavailable")
        registrar = registration.get("registrar")
        st.markdown("**Registrar**")
        st.write(registrar if isinstance(registrar, str) and not registrar.isdigit() else "Not disclosed by registry")
        owner_status = str(registration.get("owner_status", "UNKNOWN")).upper()
        st.markdown("**Registrant details**")
        st.write("Privacy protected or not provided" if "REDACTED" in owner_status or owner_status == "UNKNOWN" else "Available in registry record")
    with registration_col:
        st.markdown("**TLS certificate**")
        cert_valid = tls.get("certificate_valid")
        st.write("Valid" if cert_valid is True else "Invalid" if cert_valid is False else "Could not verify")
        expiry = tls.get("not_after")
        st.markdown("**Certificate expires**")
        st.write(expiry if isinstance(expiry, str) else "Unavailable")
        st.markdown("**DNS**")
        st.write(f"Resolved · {dns.get('resolved_ip_count', 0)} address(es)" if dns.get("status") == "SUCCESS" else "Could not verify")
        st.markdown("**Threat reputation**")
        malicious = reputation.get("malicious_provider_count", 0)
        provider_count = reputation.get("provider_count", 0)
        rep_status = str(reputation.get("reputation_status", "UNKNOWN")).upper()
        if malicious:
            rep_text = f"Listed by {malicious} of {provider_count} checked source(s)"
        elif rep_status in {"SAFE", "CLEAN", "NO_MATCH"}:
            rep_text = f"No match in {provider_count} checked source(s)"
        else:
            rep_text = "Unconfirmed — no reliable reputation result"
        st.write(rep_text)

    st.markdown("**Webpage inspection**")
    if web.get("status") == "ANALYZED":
        links = features.get("link_count")
        forms = features.get("form_count")
        parts = ["Static page inspection completed"]
        if isinstance(web.get("title"), str) and web["title"].strip():
            st.write(f"Page title: {web['title'][:200]}")
        if isinstance(fetch.get("status_code"), int):
            parts.append(f"HTTP {fetch['status_code']}")
        if isinstance(links, int):
            parts.append(f"{links} links")
        if isinstance(forms, int):
            parts.append(f"{forms} forms")
        if dynamic.get("execution_mode") == "NOT_EXECUTED":
            parts.append("page scripts were not executed")
        st.write(" · ".join(parts))
    else:
        st.write("Page content could not be fully inspected")

    if probability is None:
        ml_result = result.get("ml_result") or {}
        status = str(ml_result.get("status", "MODEL_UNAVAILABLE"))
        st.warning(
            _model_status_text(status, ml_result.get("failure_reason"))
            + " This result uses observable rules only."
        )
    elif isinstance(result.get("model_version"), str):
        st.caption(f"URL model version: {result['model_version']}. The model evaluates URL patterns; domain and webpage checks are separate evidence.")

    with st.expander("How to read this result"):
        st.write(f"Evidence quality index: {confidence if isinstance(confidence, (int, float)) else 'Unavailable'} / 100. This is provisional and is not a probability of correctness.")
        st.write("Evidence coverage counts scorable signals. Analysis completeness reflects applicable checks that returned usable results.")
        st.write("Domain age and TLS details describe registration and certificate observations. They do not prove that the website is trustworthy.")

    signals = result.get("top_signals") or []
    if signals:
        st.markdown("**Why it was flagged**" if verdict in {"PHISHING", "SUSPICIOUS"} else "**Observed indicators**")
        for signal in signals[:5]:
            name = signal.get("name", signal.get("signal_id", "Observed signal"))
            reason = signal.get("reason")
            st.write(f"• {name}" + (f" — {reason}" if reason else ""))

    if result.get("status") == "PARTIAL":
        st.caption("Some checks were unavailable or partial. Treat this result as incomplete.")


def _show_result(result: dict[str, Any], family: str) -> None:
    if family == "url":
        _show_url_result(result)
    else:
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
                    logging.getLogger(__name__).error(
                        "url_scan_failed error_type=%s", type(exc).__name__
                    )
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
