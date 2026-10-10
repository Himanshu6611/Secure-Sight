"""Streamlit Community Cloud entry point for SecureSight's shared Flask scanners.

The Flask test client is used as an in-process adapter, not exposed as a network
server. This keeps validation, rate limits, worker isolation and response
contracts on the existing API paths.
"""
from __future__ import annotations

import io
import html
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

    app = create_app(config)
    from app.media.models import _session

    try:
        _session()
    except Exception as exc:
        app.logger.warning(
            "media_origin_model_startup_check_failed",
            extra={"phase": "10", "diagnostic_code": type(exc).__name__[:64]},
        )
    else:
        app.logger.info("media_origin_model_startup_check_passed", extra={"phase": "10"})
    return app


def _verdict(result: dict[str, Any], family: str) -> None:
    if family == "email":
        _show_email_result(result)
        return
    if family == "image":
        _show_image_result(result)
        return

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


def _email_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Translate observed email evidence and the experimental model into guidance."""
    risk = result.get("risk") if isinstance(result.get("risk"), dict) else {}
    verdict = str(risk.get("verdict", "UNKNOWN")).upper()
    evidence = result.get("evidence")
    if not isinstance(evidence, list):
        evidence = []

    # Missing authentication is common for uploaded exports and is a limitation,
    # not itself evidence of phishing. Surface it separately from positive signals.
    informative = [
        item for item in evidence
        if isinstance(item, dict)
        and item.get("evidence_type") in {"OBSERVED", "INFERRED"}
        and item.get("indicator") != "AUTHENTICATION_UNVERIFIED"
    ]
    from app.email.evidence import REASONS
    findings = []
    for item in informative:
        reason = REASONS.get(item.get("indicator"))
        if reason:
            findings.append(reason[1])
    findings = list(dict.fromkeys(findings))[:5]

    model = result.get("email_model")
    if not isinstance(model, dict):
        model = (result.get("email_analysis") or {}).get("email_model", {})
    if not isinstance(model, dict):
        model = {}
    estimate = model.get("estimate")
    if not isinstance(estimate, (int, float)) or not 0 <= estimate <= 1:
        estimate = None
    model_active = model.get("status") == "EXPERIMENTAL" and estimate is not None
    threshold_crossed = model.get("threshold_crossed") is True

    score = risk.get("risk_score")
    score = score if isinstance(score, (int, float)) and 0 <= score <= 100 else None
    assessment_failed = risk.get("status") == "ERROR" or verdict == "ANALYSIS_FAILED"
    if verdict == "PHISHING":
        headline = "Phishing indicators found — don’t interact"
        level = "error"
        action = (
            "Do not click links, open attachments, or share passwords or codes. "
            "Verify with the organization through a known contact method."
        )
    elif verdict == "SUSPICIOUS" or informative or threshold_crossed:
        headline = "Warning signs found — verify before acting"
        level = "warning"
        action = (
            "Avoid links and attachments until you verify the sender independently "
            "using a trusted phone number or website."
        )
    elif assessment_failed:
        headline = "Email checks were incomplete — review before acting"
        level = "info"
        action = (
            "The message text was inspected, but no linked website produced a risk score. "
            "Do not treat this as a safe verdict; verify unexpected requests independently."
        )
    elif model_active:
        headline = "The experimental model did not cross its phishing alert threshold"
        level = "info"
        action = (
            "This model misses some phishing emails. Do not treat this result as legitimate or safe. "
            "Verify unexpected payment, password, or account requests through a known contact method."
        )
    else:
        headline = "No strong warning found in checked content; model verdict unavailable"
        level = "info"
        action = (
            "The email-trained model did not run, so this is not a model-based verdict. "
            "Verify unexpected payment, password, or account requests through a known contact method."
        )

    if result.get("analysis_status") == "FAILED":
        headline = "Email analysis failed — no result was produced"
        level = "error"
        action = "Try the original .eml file or a clearer, unprotected export."

    body = result.get("body_analysis")
    if not isinstance(body, dict):
        body = {}
    snippet = result.get("content_snippet") or body.get("snippet")
    if not isinstance(snippet, str) or not snippet.strip():
        snippet = "No readable message preview is available."
    snippet = " ".join(snippet.split())
    if len(snippet) > 240:
        snippet = snippet[:237].rstrip() + "…"
    body_features = body.get("features")
    if not isinstance(body_features, dict):
        body_features = {}
    context_pattern_count = sum(value is True for value in body_features.values())
    links = result.get("urls")
    attachments = result.get("attachments")
    message = result.get("message")
    if not isinstance(links, list):
        links = []
    if not isinstance(attachments, list):
        attachments = []
    if not isinstance(message, dict):
        message = {}

    verdict_labels = {
        "PHISHING": "Unsafe",
        "SUSPICIOUS": "Suspicious",
        "LEGITIMATE": "No strong warning signs found",
        "LOW_RISK": "Low risk signals observed",
        "ANALYSIS_FAILED": "Analysis failed",
    }
    verdict_label = verdict_labels.get(verdict, "Needs review")
    if result.get("analysis_status") == "FAILED":
        verdict_label = "No result"
    if verdict == "PHISHING":
        status_detail = "Phishing indicators found"
    elif verdict == "SUSPICIOUS":
        status_detail = "Warning signs found"
    elif model_active:
        status_detail = "Experimental model alert" if threshold_crossed else "Model below warning threshold"
    elif assessment_failed:
        status_detail = "Analysis could not be completed"
    else:
        status_detail = "Some checks may be unavailable"

    return {
        "headline": headline,
        "level": level,
        "action": action,
        "findings": findings,
        "risk_score": score,
        "email_model": "Experimental estimate" if model_active else "Unavailable",
        "email_estimate": estimate,
        "email_model_alert": threshold_crossed,
        "verdict_label": verdict_label,
        "status_detail": status_detail,
        "snippet": snippet,
        "warning_count": len(findings),
        "context_pattern_count": context_pattern_count,
        "link_count": len(links),
        "attachment_count": len(attachments),
        "message_bytes": message.get("original_bytes"),
        "analysis_status": result.get("analysis_status", "Unavailable"),
        "body_features": body_features,
        "authentication_note": any(
            isinstance(item, dict) and item.get("indicator") == "AUTHENTICATION_UNVERIFIED"
            for item in evidence
        ),
    }


def _show_email_result(result: dict[str, Any]) -> None:
    summary = _email_result_summary(result)
    estimate = summary["email_estimate"]
    risk_value = "Not scored" if summary["risk_score"] is None else f"{summary['risk_score']:.1f}/100"
    estimate_value = "Unavailable" if estimate is None else f"{estimate:.1%}"
    snippet = html.escape(summary["snippet"])
    level = summary["level"] if summary["level"] in {"error", "warning", "info"} else "info"
    st.markdown(
        """
        <style>
        .ss-email-verdict { padding: 22px 28px; border-radius: 22px; color: #fff; margin: 8px 0 16px; }
        .ss-email-verdict.error { background: linear-gradient(110deg,#dc3434,#a91f31); }
        .ss-email-verdict.warning { background: linear-gradient(110deg,#e5a323,#bf7011); }
        .ss-email-verdict.info { background: linear-gradient(110deg,#168c98,#076772); }
        .ss-email-kicker { font-size: 12px; letter-spacing: .11em; font-weight: 750; opacity: .88; text-transform: uppercase; }
        .ss-email-verdict-line { display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; }
        .ss-email-verdict h2 { color: #fff; font-size: clamp(24px,4vw,34px); line-height:1.15; margin: 5px 0 0; }
        .ss-email-pill { border:1px solid rgba(255,255,255,.52); background:rgba(255,255,255,.16); border-radius:999px; padding:8px 14px; font-size:14px; font-weight:700; }
        .ss-email-grid { display:grid; grid-template-columns:1.55fr .8fr .8fr; gap:14px; margin: 0 0 18px; }
        .ss-email-card { background:#fff; border:1px solid #e0e5ed; border-radius:18px; padding:18px 20px; min-height:132px; box-shadow:0 2px 4px rgba(19,35,55,.08); }
        .ss-email-label { color:#8792a5; font-size:12px; font-weight:750; letter-spacing:.07em; text-transform:uppercase; }
        .ss-email-snippet { color:#142033; font-size:16px; line-height:1.5; margin-top:9px; overflow-wrap:anywhere; }
        .ss-email-value { color:#128a50; font-size:32px; font-weight:800; line-height:1.2; margin-top:9px; }
        .ss-email-value.neutral { color:#526174; font-size:24px; }
        .ss-email-detail { color:#8591a3; font-size:13px; line-height:1.4; margin-top:6px; }
        .ss-email-recommendation { border-left:4px solid #148c98; background:#f1f8f9; border-radius:8px; padding:12px 16px; margin:14px 0; color:#253547; }
        .ss-email-row { display:flex; justify-content:space-between; gap:18px; padding:12px 15px; background:#fff; border:1px solid #e0e5ed; border-radius:11px; margin:6px 0; }
        .ss-email-row span:first-child { color:#253547; font-weight:600; }
        .ss-email-row span:last-child { color:#58677a; text-align:right; overflow-wrap:anywhere; }
        @media(max-width:760px) { .ss-email-grid { grid-template-columns:1fr; gap:10px; } .ss-email-card { min-height:0; } .ss-email-verdict { padding:18px; } }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <section class="ss-email-verdict {level}">
          <div class="ss-email-kicker">Threat verdict</div>
          <div class="ss-email-verdict-line">
            <h2>{html.escape(summary['verdict_label'])}</h2>
            <span class="ss-email-pill">{html.escape(summary['status_detail'])}</span>
          </div>
        </section>
        <section class="ss-email-grid">
          <div class="ss-email-card"><div class="ss-email-label">Email content preview</div><div class="ss-email-snippet">{snippet}</div></div>
          <div class="ss-email-card"><div class="ss-email-label">Experimental model estimate</div><div class="ss-email-value {'neutral' if estimate is None else ''}">{html.escape(estimate_value)}</div><div class="ss-email-detail">Not a correctness probability</div></div>
          <div class="ss-email-card"><div class="ss-email-label">Observed warning signs</div><div class="ss-email-value">{summary['warning_count']}</div><div class="ss-email-detail">From checked message evidence</div></div>
        </section>
        """,
        unsafe_allow_html=True,
    )
    if estimate is None:
        st.caption("No experimental email-model estimate was produced for this scan.")
    else:
        st.caption(
            "Experimental estimate learned from historical labeled-email features; it is not a correctness probability. "
            "In its held-out test it detected about half of phishing messages, so a low score cannot rule phishing out."
        )

    if summary["findings"]:
        st.markdown("**Why it was flagged**")
        for finding in summary["findings"]:
            st.write(f"• {finding}")
    else:
        st.markdown("**How to read this result**")
        if summary["email_estimate"] is None:
            st.write("The email-trained model did not run, so this scan has no model-based verdict.")
        elif summary["email_model_alert"]:
            st.write("The experimental model crossed its phishing warning threshold. This is a warning, not proof.")
        else:
            st.write("The experimental model stayed below its warning threshold; it can still miss phishing emails.")
    if summary["authentication_note"]:
        st.caption("Sender authentication could not be independently verified from this uploaded file.")
    st.markdown("**Recommended next step**")
    st.info(summary["action"])

    diagnostics = [
        ("Analysis status", summary["analysis_status"]),
        ("Linked-site / email warning score", risk_value),
        ("Experimental email-model estimate", estimate_value),
        ("Observed warning signs", summary["warning_count"]),
        ("Context patterns observed", summary["context_pattern_count"]),
        ("Destination links checked", summary["link_count"]),
        ("Attachments checked", summary["attachment_count"]),
        ("Uploaded message size", f"{summary['message_bytes']:,} bytes" if isinstance(summary["message_bytes"], int) else "Unavailable"),
    ]
    with st.expander("View technical diagnostic breakdown", expanded=True):
        for label, value in diagnostics:
            st.markdown(
                f'<div class="ss-email-row"><span>{html.escape(str(label))}</span>'
                f'<span>{html.escape(str(value))}</span></div>',
                unsafe_allow_html=True,
            )
        if summary["body_features"]:
            observed = [name.replace("_", " ").title() for name, value in summary["body_features"].items() if value is True]
            st.write("Observed language patterns: " + (", ".join(observed) if observed else "None detected"))
        st.markdown("**Evidence and technical details**")
        st.json(result, expanded=False)


def _image_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Present threat evidence separately from the experimental AI-origin estimate."""
    assessment = result.get("assessment") if isinstance(result.get("assessment"), dict) else {}
    verdict = str(assessment.get("verdict", "UNKNOWN")).upper()
    artifact = result.get("artifact") if isinstance(result.get("artifact"), dict) else {}
    metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
    quality = result.get("quality") if isinstance(result.get("quality"), dict) else {}
    forensics = result.get("forensics") if isinstance(result.get("forensics"), dict) else {}
    provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
    model = result.get("synthetic_media") if isinstance(result.get("synthetic_media"), dict) else {}
    ocr = result.get("ocr") if isinstance(result.get("ocr"), dict) else {}
    qr = result.get("qr") if isinstance(result.get("qr"), dict) else {}
    investigation = result.get("investigation") if isinstance(result.get("investigation"), dict) else {}
    coverage = investigation.get("coverage") if isinstance(investigation.get("coverage"), dict) else {}

    probability = model.get("model_score", model.get("synthetic_probability"))
    if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not 0 <= probability <= 1:
        probability = None
    model_status = str(model.get("analysis_status", "MODEL_UNAVAILABLE")).upper()
    model_is_usable = model_status == "EXPERIMENTAL_ESTIMATE" and probability is not None
    classification = str(model.get("classification", "")).upper()
    if not model_is_usable:
        model_value = "Unavailable"
        model_detail = "Experimental AI-pattern estimate unavailable"
    else:
        model_value = f"{probability:.1%}"
        model_detail = ("AI-generation pattern flagged · experimental score"
                        if classification == "AI_GENERATED_PATTERN"
                        else "No AI-generation pattern flagged · experimental score")

    labels = {
        "PHISHING": ("Unsafe indicators found", "error", "Threat indicators found"),
        "SUSPICIOUS": ("Suspicious image or destination", "warning", "Review before acting"),
        "LEGITIMATE": ("No strong threat signs found", "info", "Threat screening only"),
        "UNKNOWN": ("Threat screening needs review", "info",
                    "AI-origin estimate available" if model_is_usable else "Threat checks incomplete"),
    }
    headline, level, pill = labels.get(verdict, labels["UNKNOWN"])

    c2pa = str(provenance.get("status", "UNAVAILABLE")).upper()
    provenance_labels = {
        "VALID": "Signed provenance found",
        "PRESENT_UNVERIFIED": "Provenance found; trust not verified",
        "INVALID": "Provenance signature invalid",
        "ERROR": "Could not inspect provenance",
        "ABSENT": "No C2PA provenance found",
        "UNSUPPORTED": "Provenance format unsupported",
    }
    provenance_value = provenance_labels.get(c2pa, "Could not check provenance")
    if c2pa == "VALID" and provenance.get("trusted") is not True:
        provenance_value = "Signed, but issuer trust is unverified"

    width, height = metadata.get("width"), metadata.get("height")
    dimensions = f"{width:,} × {height:,} px" if isinstance(width, int) and isinstance(height, int) else "Unavailable"
    image_format = artifact.get("format") or artifact.get("mime") or "Unavailable"
    if isinstance(image_format, str):
        image_format = image_format.upper().replace("IMAGE/", "")
    image_name = artifact.get("filename")
    if not isinstance(image_name, str) or not image_name:
        image_name = f"{image_format} image"
    ocr_words = ocr.get("words") if isinstance(ocr.get("words"), list) else []
    qr_items = qr.get("items") if isinstance(qr.get("items"), list) else []
    linked = result.get("linked_analysis") if isinstance(result.get("linked_analysis"), list) else []
    risk = assessment.get("risk_score")
    risk_value = f"{risk:.1f}/100" if isinstance(risk, (int, float)) and 0 <= risk <= 100 else "Not scored"

    evidence_count = len(result.get("evidence", [])) if isinstance(result.get("evidence"), list) else 0
    measurements = []
    for key, label, suffix in (
        ("recompression_mean_absolute_error", "Recompression pixel difference (mean absolute error)", ""),
        ("median_residual_variance", "Median residual variance", ""),
        ("jpeg_quantization_tables", "JPEG quantization tables", ""),
        ("high_frequency_energy_fraction", "High frequency energy fraction", "%"),
        ("edge_gradient_mean", "Edge gradient mean", ""),
    ):
        value = forensics.get(key)
        if isinstance(value, (int, float)) and 0 <= value < float("inf"):
            display = f"{value * 100:.2f}%" if suffix == "%" else f"{value:,.4f}" if suffix == "" and key != "jpeg_quantization_tables" else str(value)
            measurements.append((label, display))
    textures = forensics.get("local_texture_variances")
    if isinstance(textures, list):
        measurements.append(("Texture regions measured", str(len(textures))))
    return {
        "headline": headline,
        "level": level,
        "pill": pill,
        "risk_value": risk_value,
        "model_value": model_value,
        "model_detail": model_detail,
        "model_available": model_is_usable,
        "model_classification": classification or "Unavailable",
        "model_threshold": model.get("decision_threshold"),
        "model_test_metrics": model.get("test_metrics") if isinstance(model.get("test_metrics"), dict) else {},
        "image_format": image_format,
        "image_name": image_name,
        "dimensions": dimensions,
        "provenance": provenance_value,
        "provenance_status": c2pa,
        "metadata_status": metadata.get("status", "Unavailable"),
        "metadata_present": metadata.get("exif_present"),
        "quality_status": quality.get("status", "Unavailable"),
        "ocr_status": ocr.get("status", "Unavailable"),
        "ocr_word_count": len(ocr_words),
        "qr_status": qr.get("status", "Unavailable"),
        "qr_count": len(qr_items),
        "linked_count": len(linked),
        "evidence_count": evidence_count,
        "measurements": measurements,
        "measurement_count": len(measurements),
        "coverage": coverage,
        "analysis_status": result.get("analysis_status", "Unavailable"),
    }


def _show_image_result(result: dict[str, Any]) -> None:
    summary = _image_result_summary(result)
    level = summary["level"] if summary["level"] in {"error", "warning", "info"} else "info"
    st.markdown(
        """
        <style>
        .ss-image-verdict { padding:22px 28px; border-radius:22px; color:#fff; margin:8px 0 16px; background:linear-gradient(110deg,#168c98,#076772); }
        .ss-image-verdict.needs-review { background:linear-gradient(110deg,#168c98,#076772); }
        .ss-image-verdict.error { background:linear-gradient(110deg,#dc3434,#a91f31); }
        .ss-image-verdict.warning { background:linear-gradient(110deg,#e5a323,#bf7011); }
        .ss-image-kicker { font-size:12px; letter-spacing:.11em; font-weight:750; opacity:.88; text-transform:uppercase; }
        .ss-image-line { display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; }
        .ss-image-verdict h2 { color:#fff; font-size:clamp(24px,4vw,34px); line-height:1.15; margin:5px 0 0; }
        .ss-image-pill { border:1px solid rgba(255,255,255,.52); background:rgba(255,255,255,.16); border-radius:999px; padding:8px 14px; font-size:14px; font-weight:700; }
        .ss-image-grid { display:grid; grid-template-columns:1.55fr .8fr .8fr; gap:14px; margin:0 0 16px; }
        .ss-image-card { background:#fff; border:1px solid #e0e5ed; border-radius:18px; padding:18px 20px; min-height:122px; box-shadow:0 2px 4px rgba(19,35,55,.08); }
        .ss-image-label { color:#8792a5; font-size:12px; font-weight:750; letter-spacing:.07em; text-transform:uppercase; }
        .ss-image-value { color:#26384a; font-size:25px; font-weight:800; line-height:1.2; margin-top:12px; overflow-wrap:anywhere; }
        .ss-image-value.neutral { color:#526174; font-size:23px; }
        .ss-image-file { color:#142033; font-size:16px; line-height:1.45; margin-top:12px; overflow-wrap:anywhere; }
        .ss-image-detail { color:#8591a3; font-size:13px; line-height:1.45; margin-top:7px; }
        .ss-image-note { border-left:4px solid #148c98; background:#f1f8f9; border-radius:8px; padding:12px 16px; margin:14px 0; color:#253547; }
        .ss-image-row { display:flex; justify-content:space-between; gap:18px; padding:12px 15px; background:#fff; border:1px solid #e0e5ed; border-radius:11px; margin:6px 0; }
        .ss-image-row span:first-child { color:#253547; font-weight:600; }
        .ss-image-row span:last-child { color:#58677a; text-align:right; overflow-wrap:anywhere; }
        @media(max-width:760px) { .ss-image-grid { grid-template-columns:1fr; gap:10px; } .ss-image-card { min-height:0; } .ss-image-verdict { padding:18px; } }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <section class="ss-image-verdict {level} {'needs-review' if summary['headline'] == 'Threat screening needs review' else ''}">
          <div class="ss-image-kicker">Threat verdict</div>
          <div class="ss-image-line"><h2>{html.escape(summary['headline'])}</h2>
            <span class="ss-image-pill">{html.escape(summary['pill'])}</span></div>
        </section>
        <section class="ss-image-grid">
          <div class="ss-image-card"><div class="ss-image-label">Image media file</div>
            <div class="ss-image-file">{html.escape(str(summary['image_name']))}</div>
            <div class="ss-image-detail">{html.escape(str(summary['image_format']))} · {html.escape(summary['dimensions'])}</div></div>
          <div class="ss-image-card"><div class="ss-image-label">Experimental AI-pattern score</div>
            <div class="ss-image-value neutral">{html.escape(summary['model_value'])}</div>
            <div class="ss-image-detail">{html.escape(summary['model_detail'])}</div></div>
          <div class="ss-image-card"><div class="ss-image-label">Forensic signals</div>
            <div class="ss-image-value">{summary['measurement_count']}</div>
            <div class="ss-image-detail">Measured properties · no anomaly verdict</div></div>
        </section>
        """,
        unsafe_allow_html=True,
    )
    if summary["model_available"]:
        origin_note = (
            f"{summary['model_detail']}. This score is not a probability or proof that an image is AI-made. "
            "The model was evaluated on one licensed image dataset only; it was not evaluated for face deepfakes, "
            "edits, or every image generator. A result below threshold does not prove camera origin."
        )
    else:
        origin_note = (
            "The experimental AI-image model did not produce an estimate for this scan. SecureSight cannot tell whether this image was AI-generated or manipulated. "
            "Missing provenance does not mean an image is fake, and a generated image is not automatically unsafe."
        )
    st.info(origin_note)
    st.markdown("**What we checked**")
    st.write(
        f"Image details: {summary['image_format']} · {summary['dimensions']}. "
        f"Metadata: {summary['metadata_status']}; EXIF {'found' if summary['metadata_present'] is True else 'not found' if summary['metadata_present'] is False else 'unknown'}. "
        f"Text reading: {summary['ocr_status']} ({summary['ocr_word_count']} words); "
        f"QR check: {summary['qr_status']} ({summary['qr_count']} found); "
        f"linked destinations analyzed: {summary['linked_count']}. "
        f"Threat screening: {summary['risk_value']}."
    )
    if summary["provenance_status"] == "VALID":
        claims = (result.get("provenance") or {}).get("claims", [])
        if claims:
            agents = list(dict.fromkeys(
                claim.get("software_agent") for claim in claims
                if isinstance(claim, dict) and isinstance(claim.get("software_agent"), str)
            ))
            if agents:
                st.write("Credential claims name the editing or generation tool: " + ", ".join(agents[:3]))
    with st.expander("View technical diagnostic breakdown", expanded=True):
        rows = [
            ("Image format", summary["image_format"]),
            ("Image media file", summary["image_name"]),
            ("Image dimensions", summary["dimensions"]),
            ("Experimental AI-pattern score", summary["model_value"] + " — " + summary["model_detail"]),
            ("Model classification", summary["model_classification"]),
            ("Model decision threshold", f"{summary['model_threshold']:.1%}" if isinstance(summary["model_threshold"], (int, float)) else "Unavailable"),
            ("C2PA provenance", summary["provenance"]),
            ("Image metadata", summary["metadata_status"]),
            ("Image quality", summary["quality_status"]),
            ("OCR text found", summary["ocr_word_count"]),
            ("QR codes found", summary["qr_count"]),
            ("Linked destinations analyzed", summary["linked_count"]),
            ("Observable evidence items", summary["evidence_count"]),
            ("Analysis status", summary["analysis_status"]),
        ]
        rows.extend(summary["measurements"])
        for label, value in rows:
            st.markdown(
                f'<div class="ss-image-row"><span>{html.escape(str(label))}</span>'
                f'<span>{html.escape(str(value))}</span></div>',
                unsafe_allow_html=True,
            )
        st.markdown("**Evidence and limits**")
        st.caption("Forensic measurements are raw image properties, not anomaly scores. The experimental AI-pattern score is uncalibrated and dataset-limited; it does not detect all deepfakes or prove an image is real. Measured properties and missing metadata do not establish image origin or authenticity.")
        st.json(result, expanded=False)


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


def _url_verdict_text(
    verdict: str,
    *,
    risk_score: Any = None,
    ml_probability: Any = None,
    model_available: bool = False,
    webpage_analyzed: bool = False,
) -> tuple[str, str]:
    if verdict == "PHISHING":
        return "Unsafe — threat indicators found", "error"
    if verdict == "SUSPICIOUS":
        return "Suspicious — verify before opening", "warning"
    if verdict in {"LEGITIMATE", "LOW_RISK"}:
        return "No strong threat indicators found", "success"
    # Summarize low-risk evidence in plain language while keeping UNKNOWN as
    # the actual verdict whenever supporting intelligence is incomplete.
    if (
        verdict == "UNKNOWN"
        and model_available
        and webpage_analyzed
        and isinstance(risk_score, (int, float))
        and 0 <= risk_score < 40
        and isinstance(ml_probability, (int, float))
        and 0 <= ml_probability < 0.15
    ):
        return "Low risk — no clear threat found", "info"
    return "We could not finish enough checks to decide", "info"


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
    risk = result.get("risk_score")
    probability = result.get("ml_probability")
    web = result.get("web_intelligence") or {}
    model_available = result.get("model_available") is True and (result.get("ml_result") or {}).get("status") == "OK"
    webpage_analyzed = web.get("status") == "ANALYZED"
    label, level = _url_verdict_text(
        verdict, risk_score=risk, ml_probability=probability,
        model_available=model_available, webpage_analyzed=webpage_analyzed,
    )
    message = f"**{label}**"
    if level == "error":
        st.error(message)
    elif level == "warning":
        st.warning(message)
    elif level == "success":
        st.success(message)
    else:
        st.info(message)

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
    if verdict == "UNKNOWN" and label.startswith("Low risk"):
        details = []
        if isinstance(probability, (int, float)):
            details.append(f"The trained URL model estimates {probability:.1%} phishing risk.")
        if webpage_analyzed:
            features = web.get("combined_web_features") or {}
            links = features.get("link_count")
            forms = features.get("form_count")
            page_checks = []
            if isinstance(links, int):
                page_checks.append(f"{links} links found")
            if isinstance(forms, int):
                page_checks.append(f"{forms} forms found")
            if page_checks:
                details.append("Static webpage inspection: " + ", ".join(page_checks) + ".")
        details.append(
            "Some reputation, history, or crawl checks may be unavailable; this is low risk, not a confirmed safe verdict."
        )
        st.info(" ".join(details))
    elif verdict == "UNKNOWN":
        st.info("One or more important checks did not return enough evidence for a reliable decision.")

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

    if result.get("status") == "PARTIAL" and verdict != "UNKNOWN":
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
    artifact = data.get("artifact")
    if isinstance(artifact, dict):
        clean_name = filename.replace("\\", "/").rsplit("/", 1)[-1]
        artifact["filename"] = "".join(char for char in clean_name if char.isprintable())[:160]
    return data


def _request_email(filename: str, content: bytes) -> dict[str, Any]:
    app = _flask_app()
    with app.test_client() as client:
        response = None
        # A saturated scan semaphore returns a definite 503 before the email
        # endpoint accepts or queues the upload. Wait briefly and retry once so
        # a transient burst does not become a confusing submission failure.
        for attempt in range(2):
            response = client.post(
                "/api/v1/email/analyze",
                data={"file": (io.BytesIO(content), filename)},
                content_type="multipart/form-data",
            )
            if response.status_code != 503 or attempt == 1:
                break
            retry_after = response.headers.get("Retry-After", "1")
            try:
                delay = min(5, max(1, int(retry_after)))
            except (TypeError, ValueError):
                delay = 1
            time.sleep(delay)
        job = response.get_json(silent=True)
        if response.status_code != 202 or not isinstance(job, dict):
            error = job.get("error", {}) if isinstance(job, dict) else {}
            code = error.get("code") if isinstance(error, dict) else None
            messages = {
                "PROVIDER_UNAVAILABLE": (
                    "The scanner is busy right now. Your email was not queued; "
                    "please wait a few seconds and try again."
                ),
                "RATE_LIMITED": (
                    "Too many scans were submitted recently. Please wait before trying again."
                ),
                "EMAIL_QUEUE_FULL": (
                    "The email analysis queue is full. Your email was not queued; "
                    "please try again shortly."
                ),
                "EMAIL_JOB_STORE_UNAVAILABLE": (
                    "The protected email job store is temporarily unavailable. "
                    "Your email was not queued; please try later."
                ),
                "EMAIL_WORKER_UNAVAILABLE": (
                    "The email analysis worker could not start. Your email was not queued; "
                    "please try again shortly."
                ),
                "DOCUMENT_TEXT_UNAVAILABLE": (
                    "No readable text was found in this file, even after PDF OCR. "
                    "The PDF may be blank, damaged or too low quality to read."
                ),
                "DOCUMENT_OCR_UNAVAILABLE": "Scanned PDF reading is temporarily unavailable. Please try again later or upload the original .eml message.",
                "DOCUMENT_OCR_TIMEOUT": "The scanned PDF took too long to read. Try a smaller or clearer PDF.",
                "DOCUMENT_OCR_FAILED": "The scanned PDF could not be read. Try a clearer scan or upload the original .eml message.",
                "DOCUMENT_PARSE_FAILED": "This document could not be read. Try exporting it again or upload the original .eml message.",
                "ENCRYPTED_DOCUMENT_UNSUPPORTED": "This document is password-protected. Remove the password before analyzing it.",
                "DOCUMENT_RESOURCE_LIMIT": "This document exceeds the analysis limits (maximum 20 PDF pages and bounded text size).",
                "EMAIL_RESOURCE_LIMIT": "The email file is empty or exceeds the 2 MB analysis limit.",
                "UNSUPPORTED_EMAIL_FORMAT": "Choose an .eml, .pdf, .docx or .xml file.",
                "DOCUMENT_TYPE_MISMATCH": "The file contents do not match its extension. Choose a valid .eml, .pdf, .docx or .xml file.",
                "INVALID_EMAIL": "The uploaded file is not a valid email or supported email document.",
            }
            message = messages.get(code, "The email could not be submitted for analysis. Please retry later.")
            raise RuntimeError(message)
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
        email_file = st.file_uploader(
            "Choose an email or email export",
            type=["eml", "pdf", "docx", "xml"],
            key="email_file",
            max_upload_size=2,
        )
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
