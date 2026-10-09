"""Pure deterministic scoring of existing intelligence, with a replayable audit."""
import copy
from .config import load_config, validate_config, config_digest
from .schemas import RiskError
from .signals import collect_signals
from .aggregation import aggregate
from .confidence import confidence
from .verdict import verdict, severity
from .behavior import incorporate_behavior
from .brand import explanation_observations

class RiskScoringEngine:
    def __init__(self, config=None):
        self._config=load_config() if config is None else validate_config(config)
        self._digest=config_digest(self._config)

    @property
    def config(self):
        return copy.deepcopy(self._config)

    def calculate(self, analysis_context):
        try:
            signals,stages,flags=collect_signals(analysis_context,self._config)
            brand_evidence = explanation_observations(analysis_context.get("brand_intelligence"))
            if analysis_context.get("brand_intelligence"):
                brand = analysis_context["brand_intelligence"]
                stages["brand"] = "AVAILABLE" if brand.get("primary_brand") and brand["status"] != "UNAVAILABLE" else "UNAVAILABLE"
                stages["historical"] = "PARTIAL" if brand.get("historical_analysis", {}).get("status") == "PARTIAL" else "UNAVAILABLE"
                stages["crawl"] = "AVAILABLE" if brand.get("crawl", {}).get("status") == "ANALYZED" else "PARTIAL"
            behavior_evidence, behavior_points, behavior_status = incorporate_behavior(analysis_context, flags, self._config)
            if behavior_status:
                stages["redirect"] = "AVAILABLE" if behavior_status == "ANALYZED" else "UNAVAILABLE"
            score,categories,coverage,category_audit,signals=aggregate(signals,self._config)
            certainty,contradictions,sources,confidence_audit=confidence(signals,coverage,flags,self._config)
            ids={s.signal_id:s for s in signals}
            harvesting=(ids["html.external_credentials"].normalized_value or 0)>0 and (ids["brand.mismatch"].normalized_value or 0)>0
            floors=[]
            if score is not None and harvesting:
                floor=self._config["floors"]["corroborated_credential_harvesting"]
                floors.append({"rule":"CORROBORATED_CREDENTIAL_HARVESTING","minimum":floor})
                if flags["model_calibrated"] and flags["ml_probability"] is not None and flags["ml_probability"]>=self._config["verdict"]["high_ml_probability"]:
                    floor=max(floor,self._config["floors"]["model_and_corroborated_harvesting"])
                    floors.append({"rule":"MODEL_AND_CORROBORATED_HARVESTING","minimum":floor})
                if flags["reputation_malicious"]:
                    floor=max(floor,self._config["floors"]["confirmed_reputation_and_harvesting"])
                    floors.append({"rule":"CONFIRMED_REPUTATION_AND_HARVESTING","minimum":floor})
                final=max(score,floor)
            else:
                final=score
            if final is not None and behavior_points:
                effective_points = min(100., final + behavior_points) - final
                final += effective_points
                for item in behavior_evidence:
                    if item["score_contribution"]:
                        item["score_contribution"] = effective_points
                floors.append({"rule":"BOUNDED_BEHAVIOR_ADJUSTMENT", "points":effective_points})
            if final is not None:
                final=round(min(100.,max(0.,final)),4)
            # Missing/partial supported intelligence cannot authorize a safety label.
            flags["analysis_partial"] = any(value not in {"AVAILABLE", "NOT_APPLICABLE"} for value in stages.values())
            decision=verdict(final,certainty,coverage,flags,sources,contradictions,self._config)
            applicable=[value for value in stages.values() if value!="NOT_APPLICABLE"]
            completeness=100*sum(value=="AVAILABLE" for value in applicable)/len(applicable)
            missing=[{"signal_id":s.signal_id,"state":s.state,"source":s.source} for s in signals if s.state not in {"AVAILABLE","NOT_APPLICABLE"}]
            warnings=[{"code":name.upper()+"_"+value,"message":name.replace("_"," ").capitalize()+" intelligence is not fully available."}
                for name,value in stages.items() if value not in {"AVAILABLE","NOT_APPLICABLE"}]
            if flags["analysis_partial"]:
                warnings.append({"code":"SAFETY_WITHHELD_PARTIAL", "message":"Incomplete intelligence cannot establish a legitimate verdict; observed threat evidence may still support a risk verdict."})
            warnings.append({"code":"CONFIDENCE_NOT_CALIBRATED","message":"Confidence is a provisional evidence-quality index, not a validated correctness probability."})
            warnings.append({"code":"DYNAMIC_ANALYSIS_SKIPPED","message":"Only static webpage analysis is supported; browser behavior was not assessed."})
            warnings.append({"code":"EXTERNAL_RESOURCE_ANALYSIS_INCOMPLETE","message":"External resources were not executed or fetched; available references are inspected statically."})
            if behavior_status and behavior_status != "ANALYZED":
                warnings.append({"code":"BEHAVIOR_"+behavior_status, "message":"Redirect analysis is incomplete; no safety conclusion was inferred."})
            if behavior_status and (analysis_context["behavior_intelligence"]["features"]["meta_refresh_detected"] or analysis_context["behavior_intelligence"]["features"]["js_redirect_detected"]):
                warnings.append({"code":"CLIENT_NAVIGATION_UNOBSERVED", "message":"A static client-navigation target was detected but not executed; the eventual destination is unverified."})
            if not flags["model_calibrated"]:
                warnings.append({"code":"MODEL_CALIBRATION_UNCONFIRMED","message":"The calibrated-model confidence component is unavailable."})
            if flags.get("reputation_suspicious"):
                warnings.append({"code":"REPUTATION_MATCH_UNCONFIRMED","message":"Suspicious reputation is not confirmed current maliciousness."})
            signal_dicts=[s.to_dict() for s in signals]
            top=sorted((s for s in signal_dicts if s["selected"] and s["normalized_value"]>=self._config["evidence"]["minimum_normalized"]),
                key=lambda s:(-s["contribution"],-s["normalized_value"],-s["confidence"],s["signal_id"]))[:self._config["evidence"]["top_k"]]
            return {
                "status":"OK","assessment_version":self._config["assessment_version"],
                "scoring_config_version":self._config["version"],"scoring_config_sha256":self._digest,
                "risk_score":round(final,4) if final is not None else None,"risk_score_kind":"heuristic observed risk; not a safety probability",
                "severity":severity(final,self._config),"verdict":decision,"confidence":round(certainty,4),
                "confidence_kind":confidence_audit["kind"],"confidence_calibrated":False,
                "evidence_coverage":round(coverage,4),"analysis_completeness":round(completeness,4),
                "ml_probability":flags["ml_probability"],"model_version":flags["model_version"],
                "feature_schema_version":flags["feature_schema_version"],
                "category_scores":{k:round(v,4) if v is not None else None for k,v in categories.items()},
                "category_availability":{k:round(v["observed_group_fraction"]*100,4) for k,v in category_audit.items()},
                "top_signals":top,"signals":signal_dicts,"missing_signals":missing,
                "agreement":"HIGH" if len(sources)>=2 and not contradictions else "LOW" if contradictions else "LIMITED",
                "independent_risk_sources":sorted(sources),"contradictions":contradictions,"warnings":warnings,
                "behavioral_evidence":behavior_evidence,"behavior_status":behavior_status,"behavior_feature_version":"8.0.0" if behavior_status else None,
                "brand_evidence":brand_evidence,"brand_feature_version":"9.0.0" if analysis_context.get("brand_intelligence") else None,
                "audit":{"base_risk_score":score,"risk_adjustments":floors,"category_details":category_audit,
                    "confidence":confidence_audit,"stages":stages,"thresholds":copy.deepcopy(self._config["verdict"])}
            }
        except RiskError as exc:
            return self.failure(exc.code)
        except (TypeError,ValueError,KeyError,OverflowError,ZeroDivisionError):
            return self.failure("RISK_INPUT_INVALID")

    def assess_media(self, media):
        """Uncalibrated forensic observations never add Phase 6 risk points."""
        candidates = [item.get("assessment", {}) for item in media.get("linked_analysis", [])
            if item.get("assessment", {}).get("status") == "OK"
            and item.get("assessment", {}).get("scoring_config_sha256") == self._digest
            and isinstance(item.get("assessment", {}).get("risk_score"), (int, float))]
        if candidates:
            result = copy.deepcopy(max(candidates, key=lambda item: item["risk_score"]))
            if result["verdict"] == "LEGITIMATE":
                result["verdict"] = "UNKNOWN"
            result["assessment_scope"] = "linked_destination_risk; image_authenticity_unknown"
        else:
            result = self.failure("MEDIA_AUTHENTICITY_UNVERIFIED")
            result.update(status="PARTIAL", verdict="UNKNOWN", confidence=None,
                confidence_kind="unavailable; no validated image-authenticity model",
                evidence_coverage=None, analysis_completeness=None)
            result["error"] = {"code": "MEDIA_AUTHENTICITY_UNVERIFIED",
                "message": "No validated image-authenticity model is configured; the image origin cannot be assessed."}
            result["warnings"] = [{"code": "MEDIA_AUTHENTICITY_UNVERIFIED",
                "message": "Image text and metadata can be inspected, but no validated model can determine whether this image is AI-generated or manipulated."}]
        result.update(media_policy_version="10.0.0", media_risk_points=0, confidence_calibrated=False)
        return result

    def assess_email(self, email):
        """Conservative email policy; weak identity/auth/language is unscored."""
        from app.email.evidence import REASONS
        observed = set()
        for item in email["evidence"]:
            if item.get("indicator") not in REASONS or item.get("email_id") != email["message"]["email_id"]:
                return self.failure("EMAIL_EVIDENCE_INVALID")
            observed.add(item["indicator"])
        linked = [row["analysis"].get("assessment", {}) for row in email["urls"]]
        candidates = [r for r in linked if r.get("status") == "OK" and r.get("scoring_config_sha256") == self._digest
                      and type(r.get("risk_score")) in {int, float} and 0 <= r["risk_score"] <= 100]
        result = copy.deepcopy(max(candidates, key=lambda r: r["risk_score"])) if candidates else self.failure("EMAIL_INTELLIGENCE_INCOMPLETE")
        result.update(status="PARTIAL", email_policy_version="11.0", assessment_scope="EMAIL_WITH_LINKED_DESTINATION_EVIDENCE",
            confidence=None, confidence_kind="overall email confidence unavailable; linked website confidence is separate", confidence_calibrated=False)
        if not candidates:
            result.update(evidence_coverage=None, analysis_completeness=None)
            result["error"] = {"code": "EMAIL_INTELLIGENCE_INCOMPLETE",
                "message": "No linked destination produced a complete risk assessment; uploaded email headers do not authenticate the sender."}
            result["warnings"] = [{"code": "EMAIL_INTELLIGENCE_INCOMPLETE",
                "message": "No linked destination produced a complete risk assessment. Confirm the sender through a known contact method; uploaded headers can be forged."}]
        if result["verdict"] in {"LEGITIMATE", "ANALYSIS_FAILED"}:
            result["verdict"] = "UNKNOWN"
        floors = []
        if "BEC_CONTEXT_COMBINATION" in observed and observed & {"REPLY_TO_DOMAIN_MISMATCH", "DISPLAY_BRAND_DOMAIN_MISMATCH"}:
            floors.append({"rule": "BEC_WITH_IDENTITY_ANOMALY", "minimum": 60, "evidence_ids": [e["evidence_id"] for e in email["evidence"] if e["indicator"] in {"BEC_CONTEXT_COMBINATION", "REPLY_TO_DOMAIN_MISMATCH", "DISPLAY_BRAND_DOMAIN_MISMATCH"}]})
        if "DANGEROUS_ATTACHMENT" in observed:
            floors.append({"rule": "ATTACHMENT_SECURITY_WARNING", "minimum": 60, "evidence_ids": [e["evidence_id"] for e in email["evidence"] if e["indicator"] == "DANGEROUS_ATTACHMENT"]})
        if floors:
            result["risk_score"] = max(result["risk_score"] or 0, max(f["minimum"] for f in floors))
            if result["verdict"] != "PHISHING":
                result["verdict"] = "SUSPICIOUS"
            result["severity"] = severity(result["risk_score"], self._config)
        result["email_policy"] = {"version": "11.0", "floors": floors, "calibrated": False,
            "authentication_pass_reduces_risk": False, "keyword_only_points": 0, "identity_only_points": 0}
        return result

    def assess_email_batch(self, emails):
        candidates = [email["risk"] for email in emails if email["risk"].get("email_policy_version") == "11.0"
                      and type(email["risk"].get("risk_score")) in {int, float}]
        result = copy.deepcopy(max(candidates, key=lambda r: r["risk_score"])) if candidates else self.failure("EMAIL_BATCH_INTELLIGENCE_INCOMPLETE")
        result.update(assessment_scope="EXPLICIT_EMAIL_BATCH", confidence=None, campaign_risk_points=0)
        if result["verdict"] in {"LEGITIMATE", "ANALYSIS_FAILED"}:
            result["verdict"] = "UNKNOWN"
        return result

    def failure(self, code):
        return {
            "status":"ERROR","error":{"code":code,"message":"Risk assessment could not be completed."},
            "assessment_version":self._config["assessment_version"],"scoring_config_version":self._config["version"],
            "scoring_config_sha256":self._digest,"risk_score":None,"severity":"UNKNOWN","verdict":"ANALYSIS_FAILED",
            "confidence":0.,"confidence_kind":"unavailable","confidence_calibrated":False,"evidence_coverage":0.,
            "analysis_completeness":0.,"ml_probability":None,"model_version":None,"feature_schema_version":None,
            "category_scores":dict.fromkeys(self._config["categories"]),"top_signals":[],"signals":[],
            "missing_signals":[],"contradictions":[],"warnings":[{"code":code,"message":"Assessment failed; no safety verdict is available."}],
            "audit":{"thresholds":copy.deepcopy(self._config["verdict"])}
        }
