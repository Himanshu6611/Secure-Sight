"""Pure translation of Phase 6 observations with bounded, replayable output."""
import copy
import json
import hashlib
from app.risk.config import load_config, config_digest
from app.risk.normalization import normalize
from .reason_registry import load_registry, validate_registry, registry_digest
from .validation import number, validate_reason
from .ranking import rank_reasons
from .ml_explanation import translate_ml
from app.behavior.evidence import load_reasons
from app.brand.analyzer import EVIDENCE_REASONS


class ExplanationEngine:
    def __init__(self, registry=None):
        self._registry = load_registry() if registry is None else validate_registry(registry)
        self._digest = registry_digest(self._registry)
        self._risk = load_config()
        self._signals = {s["id"]: s for s in self._risk["signals"]}
        self._behavior_reasons = load_reasons()["indicators"]
        self._behavior_digest = hashlib.sha256(json.dumps(self._behavior_reasons, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def explain_media(self, media):
        """Fixed registered wording for actual unscored media observations."""
        registry = {
            "media.model_unavailable": ("DEEPFAKE", "The trained model is unavailable; synthetic and manipulation probabilities are unknown."),
            "media.ai_origin_model_observation": ("AI_IMAGE_PATTERN", "An experimental model observed patterns associated with AI-generated images in its training domain; this uncalibrated score does not prove image origin."),
            "media.measured_properties": ("MEDIA_FORENSICS", "Compression and noise measurements are uncalibrated observations, not proof of manipulation."),
            "media.insufficient_quality": ("MEDIA", "Image quality limits analysis; poor quality does not increase phishing risk."),
            "media.qr_observed": ("QR", "A QR payload was decoded. QR presence alone is not malicious."),
            "media.ocr_observed": ("OCR", "Text was extracted from the image. Extracted claims are untrusted."),
            "media.provenance_absent": ("PROVENANCE", "Content Credentials were not found; absence does not prove an image is fake."),
        }
        artifact_hash = media["artifact"]["sha256"]
        reasons = []
        for evidence in media["evidence"]:
            if evidence["id"] not in registry or evidence["source_sha256"] != artifact_hash or evidence["score_contribution"] != 0:
                raise ValueError("Invalid media evidence")
            category, description = registry[evidence["id"]]
            reasons.append({"reason_id": evidence["id"], "category": category,
                "description": description, "source_sha256": artifact_hash, "confidence": None, "score_contribution": 0})
        return {"explanation_version": "10.0.0", "reason_registry_sha256": hashlib.sha256(
            json.dumps(registry, sort_keys=True).encode()).hexdigest(), "reasons": reasons,
            "verdict": media["assessment"]["verdict"], "authenticity": "UNKNOWN"}

    def explain_email(self, email):
        from app.email.evidence import REASONS
        reasons = []
        ids = set()
        for evidence in email["evidence"]:
            if evidence["indicator"] not in REASONS or evidence["email_id"] != email["message"]["email_id"] or evidence["evidence_id"] in ids:
                raise ValueError("Invalid email evidence")
            ids.add(evidence["evidence_id"])
            category, wording = REASONS[evidence["indicator"]]
            reasons.append({"evidence_id": evidence["evidence_id"], "category": category, "description": wording,
                "confidence": evidence["confidence"], "source": evidence["source"], "evidence_type": evidence["evidence_type"]})
        return {"version": "11.0", "registry_sha256": hashlib.sha256(json.dumps(REASONS, sort_keys=True).encode()).hexdigest(),
            "verdict": email["risk"]["verdict"], "reasons": reasons,
            "score_adjustments": email["risk"]["email_policy"]["floors"],
            "summary": "Email evidence and linked destinations were assessed. Authentication and model gaps remain; this is not a safety guarantee."}

    @property
    def registry(self):
        return copy.deepcopy(self._registry)

    def _reason(self, signal, negative=False):
        entry = self._registry["signals"][signal["signal_id"]]
        wording = entry["negative"] if negative else entry
        kind = "MODEL_DERIVED" if entry["category"] == "ML" else "EXTERNAL" if entry["category"] == "REPUTATION" else "INFERRED" if entry["category"] in {"BRAND", "CONTENT", "NLP"} else "OBSERVED"
        evidence = {"value": signal["value"], "normalized_value": signal["normalized_value"]}
        reason = {"reason_id": signal["signal_id"] + (".risk_reducing" if negative else ""),
            "signal_id": signal["signal_id"], "category": entry["category"],
            "severity": "INFO" if negative else signal["severity"], "title": wording["title"],
            "description": wording["description"], "evidence": evidence,
            "source": signal["source"], "evidence_type": kind, "confidence": signal["confidence"],
            "score_contribution": signal["contribution"], "source_reliability": signal["confidence"],
            "independence_group": signal["category"] + ":" + signal["group"]}
        if signal["signal_id"] == "reputation.provider":
            # Describe the actual status; do not promote historical alerts to confirmed maliciousness.
            reason["title"] += " (" + signal["value"] + ")"
        return validate_reason(reason, self._registry["limits"]["max_description"])

    def _validated_signal(self, signal):
        if not isinstance(signal, dict) or not isinstance(signal.get("signal_id"), str):
            raise ValueError("Invalid signal")
        definition = self._signals.get(signal["signal_id"])
        if definition is None:
            raise ValueError("Unsupported signal")
        key = definition["category"]
        source = "phase_3_dns" if signal["signal_id"].startswith("dns.") else "phase_3_tls" if signal["signal_id"].startswith("tls.") else {
            "url": "phase_2", "domain": "phase_3_registration", "reputation": "phase_3_reputation",
            "html": "phase_4_static", "content": "phase_4_static", "brand": "phase_4_static", "ml": "phase_5"}[key]
        valid_source = signal.get("source") == source or (key == "brand" and signal.get("source") == "phase_9")
        if not valid_source or signal.get("category") != key.upper() or signal.get("group") != definition["group"]:
            raise ValueError("Invalid signal provenance")
        if type(signal.get("selected")) is not bool or signal.get("state") not in {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE", "ERROR", "PARTIAL", "SKIPPED", "TIMEOUT"}:
            raise ValueError("Invalid signal state")
        number(signal["confidence"], 0, 1)
        number(signal["contribution"], 0, 100)
        if signal["state"] != "AVAILABLE":
            if signal["value"] is not None or signal["normalized_value"] is not None or signal["selected"] or signal["contribution"]:
                raise ValueError("Unavailable evidence has a value")
            return signal
        value = signal["value"]
        if key == "reputation":
            if value not in {"SAFE", "SUSPICIOUS", "MALICIOUS"}:
                raise ValueError("Invalid reputation value")
        elif type(value) is bool:
            pass
        else:
            number(value)
        observed = normalize(value, definition)
        if abs(number(signal["normalized_value"], 0, 1)-observed) > 1e-6:
            raise ValueError("Signal normalization mismatch")
        expected = "INFO" if not observed else "HIGH" if observed >= self._risk["verdict"]["alert_min_normalized"] else "LOW"
        if signal.get("severity") != expected or (not signal["selected"] and signal["contribution"] != 0):
            raise ValueError("Invalid signal contribution/severity")
        return signal

    def explain(self, assessment, ml_result=None, web_intelligence=None):
        registry = self._registry
        messages, limits = registry["messages"], registry["limits"]
        output = {"status": "OK", "explanation_version": registry["version"], "registry_sha256": self._digest,
            "behavior_registry_version":"8.0.0", "behavior_registry_sha256":self._behavior_digest,
            "summary": messages["summary"]["ANALYSIS_FAILED"], "top_reasons": [], "positive_signals": [],
            "negative_signals": [], "ml_explanation": {"status": "UNAVAILABLE", "scope": "LOCAL", "features": []},
            "contradictions": [], "warnings": [], "missing_information": [], "score_adjustments": [],
            "behavioral_reasons": [],
            "brand_reasons": [], "brand_registry_version":"9.0.0",
            "technical": {"signals": []}}
        warnings = output["warnings"]
        def warn(code, description):
            if not any(w["code"] == code for w in warnings):
                warnings.append({"code": code, "description": description})
        warn("CONFIDENCE_NOT_CALIBRATED", messages["confidence_limit"])
        warn("DYNAMIC_ANALYSIS_SKIPPED", messages["dynamic"])
        warn("EXTERNAL_RESOURCE_ANALYSIS_INCOMPLETE", messages["external"])
        try:
            if not isinstance(assessment, dict) or assessment.get("assessment_version") != self._risk["assessment_version"] or assessment.get("scoring_config_sha256") != config_digest(self._risk):
                raise ValueError("Unsupported assessment provenance")
            verdict = assessment["verdict"]
            if verdict not in messages["summary"]:
                raise ValueError("Unsupported verdict")
            if verdict == "ANALYSIS_FAILED":
                warn("ANALYSIS_FAILED", messages["summary"][verdict])
            number(assessment["confidence"], 0, 100)
            number(assessment["evidence_coverage"], 0, 100)
            if assessment["risk_score"] is not None:
                number(assessment["risk_score"], 0, 100)
            signals = assessment["signals"]
            if not isinstance(signals, list) or len(signals) > 64:
                raise ValueError("Too many explanation inputs")
            positive, negative, seen = [], [], set()
            for item in signals:
                try:
                    signal = self._validated_signal(item)
                    identity = signal["signal_id"]
                    if identity in seen:
                        continue
                    seen.add(identity)
                    output["technical"]["signals"].append({key: signal[key] for key in (
                        "signal_id", "source", "state", "value", "normalized_value", "confidence", "contribution", "selected")})
                    if signal["state"] not in {"AVAILABLE", "NOT_APPLICABLE"}:
                        output["missing_information"].append({"signal_id": identity, "source": signal["source"],
                            "evidence_type": "MISSING", "title": messages["missing_title"],
                            "description": messages["missing_description"].format(name=registry["signals"][identity]["title"].lower())})
                    if signal["state"] == "AVAILABLE" and signal["selected"]:
                        if signal["normalized_value"] >= self._risk["evidence"]["minimum_normalized"]:
                            positive.append(self._reason(signal))
                        elif signal["normalized_value"] == 0 and "negative" in registry["signals"][identity]:
                            negative.append(self._reason(signal, True))
                except (ValueError, TypeError, KeyError):
                    warn("EXPLANATION_INPUT_OMITTED", messages["invalid"])
            # This additional observation is explicitly unscored; reuse Phase 4 counts, never parse HTML here.
            if isinstance(web_intelligence, dict) and web_intelligence.get("status") == "ANALYZED" and "html.external_credentials" in seen:
                html_signal = next(s for s in signals if s.get("signal_id") == "html.external_credentials")
                count = web_intelligence.get("combined_web_features", {}).get("password_input_count")
                if html_signal["state"] == "AVAILABLE" and type(count) is int and 0 < count <= 10000:
                    reason = {"reason_id": "html.password_inputs", "signal_id": "html.password_inputs", "category": "FORM",
                        "severity": "INFO", "title": messages["password_title"],
                        "description": messages["password_description"].format(count=count), "evidence": {"count": count},
                        "source": "phase_4_static", "evidence_type": "OBSERVED", "confidence": html_signal["confidence"],
                        "source_reliability": html_signal["confidence"], "independence_group": "HTML:credential_destination"}
                    # A password field alone has no invented score contribution and is contextual, not a positive risk reason.
                    output["technical"]["password_observation"] = validate_reason(reason, limits["max_description"])
            for observed in assessment.get("behavioral_evidence", [])[:32]:
                try:
                    code = observed["indicator"]
                    entry = self._behavior_reasons[code]
                    if observed["source"] != "phase_8" or observed["evidence_type"] not in {"OBSERVED", "INFERRED"}:
                        raise ValueError("Invalid behavior reason provenance")
                    reason = {"reason_id":code, "signal_id":code, **entry, "source":"phase_8",
                        "evidence_type":observed["evidence_type"], "confidence":number(observed["confidence"], 0, 1),
                        "source_reliability":observed["confidence"], "evidence":{"value":number(observed["value"], 0, 10000)},
                        "score_contribution":number(observed["score_contribution"], 0, 10),
                        "independence_group":"BEHAVIOR:redirect_chain"}
                    validate_reason(reason, limits["max_description"])
                    if not any(r["reason_id"] == code for r in output["behavioral_reasons"]):
                        output["behavioral_reasons"].append(reason)
                    if reason["score_contribution"] > 0:
                        positive.append(reason)
                except (ValueError, KeyError, TypeError):
                    warn("EXPLANATION_INPUT_OMITTED", messages["invalid"])
            if assessment.get("behavior_status") and assessment["behavior_status"] != "ANALYZED":
                output["missing_information"].append({"signal_id":"BEHAVIOR_ANALYSIS", "source":"phase_8",
                    "evidence_type":"MISSING", "title":messages["missing_title"],
                    "description":messages["missing_description"].format(name="redirect chain")})
            output["positive_signals"] = rank_reasons(positive, limits["max_reasons"])
            for observed in assessment.get("brand_evidence", [])[:16]:
                try:
                    code = observed["indicator"]
                    category, title, description = EVIDENCE_REASONS[code]
                    if observed["source"] != "phase_9" or observed["category"] != category or observed["score_contribution"] != 0:
                        raise ValueError("Invalid brand reason provenance")
                    output["brand_reasons"].append(validate_reason(dict(reason_id=code, signal_id=code, category=category,
                        title=title, description=description, severity="INFO", source="phase_9", evidence_type="OBSERVED",
                        evidence={"value":number(observed["value"], 1, 32)}, confidence=number(observed["confidence"], 0, 1),
                        score_contribution=0, independence_group="BRAND_HISTORY_CONTEXT"), limits["max_description"]))
                except (ValueError, KeyError, TypeError):
                    warn("EXPLANATION_INPUT_OMITTED", messages["invalid"])
            output["negative_signals"] = rank_reasons(negative, limits["max_reasons"])
            output["top_reasons"] = rank_reasons(positive, limits["top_reasons"])
            output["summary"] = messages["summary"][verdict]
            if output["top_reasons"]:
                output["summary"] += messages["reason_suffix"].format(titles="; ".join(r["title"] for r in output["top_reasons"]))
            for conflict in assessment.get("contradictions", [])[:16]:
                code = conflict.get("code") if isinstance(conflict, dict) else None
                if code in registry["contradictions"] and not any(c["reason_id"] == code for c in output["contradictions"]):
                    output["contradictions"].append({"reason_id": code, "category": "SYSTEM", "severity": "MEDIUM",
                        "source": "phase_6", "evidence_type": "CONTRADICTORY", "title": "Conflicting evidence",
                        "description": registry["contradictions"][code]})
            for adjustment in assessment.get("audit", {}).get("risk_adjustments", [])[:3]:
                if isinstance(adjustment, dict) and adjustment.get("rule") in registry["floors"]:
                    minimum = number(adjustment["minimum"], 0, 100)
                    output["score_adjustments"].append({"rule": adjustment["rule"], "minimum": minimum, "source": "phase_6",
                        "description": messages["floor"]})
                elif isinstance(adjustment, dict) and adjustment.get("rule") == "BOUNDED_BEHAVIOR_ADJUSTMENT":
                    output["score_adjustments"].append({"rule":adjustment["rule"], "points":number(adjustment["points"], 0, 10),
                        "source":"phase_6", "description":messages["behavior_adjustment"]})
            if (verdict == "PHISHING" or assessment.get("severity") == "CRITICAL") and not any(r["severity"] in {"HIGH", "CRITICAL"} for r in positive):
                warn("EXPLANATION_ASSESSMENT_INCONSISTENT", messages["consistency"])
            output["ml_explanation"] = translate_ml(ml_result, assessment, registry)
            if output["ml_explanation"]["status"] != "AVAILABLE":
                warn("ML_EXPLANATION_UNAVAILABLE", messages["ml_unavailable"])
            output["technical"]["assessment_version"] = assessment["assessment_version"]
            output["technical"]["scoring_config_sha256"] = assessment["scoring_config_sha256"]
        except (ValueError, TypeError, KeyError, AttributeError):
            output["status"] = "PARTIAL"
            warn("EXPLANATION_INPUT_OMITTED", messages["invalid"])
        if any(w["code"] in {"EXPLANATION_INPUT_OMITTED", "EXPLANATION_ASSESSMENT_INCONSISTENT"} for w in warnings):
            output["status"] = "PARTIAL"
        # Drop optional technical detail first; always retain verdict summary and limitations.
        if len(json.dumps(output, ensure_ascii=True, allow_nan=False).encode()) > limits["max_total_bytes"]:
            output["technical"] = {}
            output["positive_signals"] = output["top_reasons"]
            output["negative_signals"] = []
            output["ml_explanation"]["features"] = []
            warn("EXPLANATION_SIZE_LIMIT", messages["size_limit"])
            for key in ("missing_information", "positive_signals", "top_reasons", "contradictions", "score_adjustments", "behavioral_reasons", "brand_reasons"):
                while output[key] and len(json.dumps(output, ensure_ascii=True, allow_nan=False).encode()) > limits["max_total_bytes"]:
                    output[key].pop()
        return output
