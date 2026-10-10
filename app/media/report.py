"""Normalize executed media evidence without inventing detector results."""
import uuid

DEFAULT_CHECKS = ("c2pa", "metadata", "ai_image_detector", "manipulation_forensics")


def build(result, reverse_search=False, content_safety=False, requested_checks=None):
    provenance = result.get("provenance") or {}
    metadata = result.get("metadata") or {}
    forensics = result.get("forensics") or {}
    model = result.get("synthetic_media") or {}
    synthid = result.get("synthid") or {}
    watermark_states = {"DETECTED": "detected", "LIKELY": "likely", "POSSIBLE": "possible",
        "NOT_DETECTED": "not_detected", "NOT_CHECKED": "not_checked", "UNAVAILABLE": "not_available",
        "ERROR": "failed", "INCONCLUSIVE": "inconclusive"}
    c2pa_states = {
        "ABSENT": "not_detected",
        "VALID": "detected",
        "PRESENT_UNVERIFIED": "inconclusive",
        "INVALID": "failed",
        "ERROR": "failed",
        "UNSUPPORTED": "not_available",
    }
    c2pa_status = c2pa_states.get(str(provenance.get("status", "UNSUPPORTED")).upper(), "inconclusive")
    c2pa_limitations = []
    if not provenance.get("claims_available", False):
        c2pa_limitations.append("Detailed manifest claim fields are unavailable.")
    if c2pa_status == "not_detected":
        c2pa_limitations.append("No manifest means no supported credential was found; it does not mean the image is fake.")
    elif c2pa_status in {"detected", "inconclusive"}:
        c2pa_limitations.append("Credential claims describe provenance assertions; they do not prove depicted events are true.")
    checks = {
        "watermark": {
            "status": watermark_states.get(str(synthid.get("status", "NOT_AVAILABLE")).upper(), "inconclusive"),
            "provider": synthid.get("provider"), "score": synthid.get("score"),
            "detector_version": synthid.get("detector_version"),
            "score_semantics": synthid.get("score_semantics"),
            "limitations": (["SecureSight did not submit the image to a watermark detector.",
                "The official detector must be used manually; no detected watermark does not prove camera origin."]
                if watermark_states.get(str(synthid.get("status", "NOT_AVAILABLE")).upper()) == "NOT_CHECKED"
                else ["A watermark result only applies to the provider's supported watermark families; no result does not prove camera origin."]),
            "manual_url": "https://synthid.com/",
            "network_request": False,
        },
        "c2pa": {
            "status": c2pa_status,
            "manifest_valid": provenance.get("signature_valid"),
            "trusted": provenance.get("trusted"),
            "validation_state": provenance.get("validation_state"),
            "claims": provenance.get("claims", []),
            "claims_available": provenance.get("claims_available", False),
            "limitations": c2pa_limitations,
        },
        "metadata": {
            "status": ("detected" if metadata.get("exif_present") else "not_detected")
                if metadata.get("status") == "ANALYZED" else "failed",
            "observations": metadata,
            "limitations": ["Metadata can be edited or removed and does not prove who created an image."]
                if metadata.get("status") == "ANALYZED" else ["Image metadata could not be inspected."],
        },
        "ai_image_detector": {
            "status": "not_available" if model.get("analysis_status") == "MODEL_UNAVAILABLE" else "inconclusive",
            "model": model.get("model_name"), "score": model.get("model_score", model.get("synthetic_probability")),
            "classification": model.get("classification"),
            "score_semantics": model.get("score_semantics"),
            "decision_threshold": model.get("decision_threshold"),
            "test_metrics": model.get("test_metrics"),
            "calibrated": model.get("calibrated", False),
            "limitations": ["Experimental AI-generated-image pattern estimate; not a calibrated probability or proof of origin.",
                "Not evaluated for deepfakes, face swaps, edited real images, or generators outside the training source.",
                "A low score does not establish that an image is authentic."],
        },
        "manipulation_forensics": {
            "status": "partial" if forensics.get("status") == "ANALYZED" else "not_available",
            "model": None, "score": None, "observations": forensics,
            "limitations": ["Measured compression, texture and frequency properties are review clues, not proof of editing."],
        },
        "reverse_image_search": {
            "status": "not_available" if reverse_search else "not_checked",
            "provider": None, "matches": [], "network_request": False,
            "limitations": ["No approved visual-search provider is configured; the image was not sent to a third party.",
                "A future provider could only report indexed visual matches, not every upload or image ownership."],
        },
        "content_safety": {
            "status": "not_available" if content_safety else "not_checked",
            "model": None, "score": None,
            "limitations": ["No content-safety classifier is configured; no sexual-content conclusion was made."]
                if content_safety else [],
        },
    }
    requested = list(DEFAULT_CHECKS if requested_checks is None else requested_checks)
    if reverse_search:
        requested.append("reverse_image_search")
    if content_safety:
        requested.append("content_safety")
    completed = [name for name, value in checks.items() if value["status"] in {"detected", "not_detected"}]
    failed = [name for name, value in checks.items() if value["status"] == "failed"]
    not_checked = [name for name, value in checks.items() if value["status"] == "not_checked"]
    partial = [name for name, value in checks.items() if value["status"] == "partial"]
    inconclusive = [name for name, value in checks.items() if value["status"] == "inconclusive"]
    return {
        "scan_id": uuid.uuid4().hex,
        "status": "partial" if failed or any(value["status"] in {"not_available", "inconclusive", "partial", "not_checked"} for value in checks.values()) else "complete",
        "checks": checks,
        "coverage": {"requested": requested, "completed": completed, "failed": failed,
            "partial": partial, "inconclusive": inconclusive,
            "not_checked": not_checked,
            "unavailable": [name for name, value in checks.items() if value["status"] == "not_available"]},
        "created_at": result.get("created_at"),
        "retention": result.get("retention", "request_only"),
    }
