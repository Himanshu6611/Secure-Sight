"""Fixed trusted JSON configuration; no YAML object constructors or executable data."""
import copy
import hashlib
import json
from pathlib import Path
from .normalization import number
from .schemas import RiskError

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config/risk_scoring.json"
CATEGORIES = {"url","domain","reputation","html","content","brand","ml"}
FORMULAS = {"boolean","inverse_boolean","ramp","inverse_ramp","probability","status"}

def validate_config(config):
    code = "SCORING_CONFIGURATION_ERROR"
    try:
        config = copy.deepcopy(config)
        expected = {"version","assessment_version","policy_status","categories","severity","confidence","verdict","floors","groups","signals","model_versions","feature_schema_versions","stages","evidence","behavior"}
        if set(config) != expected or set(config["categories"]) != CATEGORIES or set(config["groups"]) != CATEGORIES:
            raise RiskError(code)
        for key in ("version","assessment_version"):
            if not isinstance(config[key], str) or not config[key] or len(config[key])>32:
                raise RiskError(code)
        if config["policy_status"] != "PROVISIONAL_NOT_CALIBRATED":
            raise RiskError(code)
        behavior = config["behavior"]
        if set(behavior) != {"version", "maximum_adjustment", "failure_blocks_definitive", "indicator_points"} or behavior["version"] != "8.0.0" or behavior["failure_blocks_definitive"] is not True:
            raise RiskError(code)
        number(behavior["maximum_adjustment"], 0, 10, code)
        if set(behavior["indicator_points"]) != {"BEHAVIOR_REDIRECT_LOOP", "BEHAVIOR_EXCESSIVE_REDIRECTS", "BEHAVIOR_HTTPS_TO_HTTP", "BEHAVIOR_DOMAIN_HOPPING"}:
            raise RiskError(code)
        for points in behavior["indicator_points"].values():
            number(points, 0, behavior["maximum_adjustment"], code)
        for key in ("model_versions","feature_schema_versions"):
            if not isinstance(config[key],list) or not config[key] or any(not isinstance(v,str) or not v for v in config[key]):
                raise RiskError(code)
        if config["stages"] != ["url","dns","tls","registration","reputation","html","content","ml"]:
            raise RiskError(code)
        if abs(sum(number(v,0,1,code) for v in config["categories"].values())-1)>1e-9:
            raise RiskError(code)
        if any(v<=0 for v in config["categories"].values()):
            raise RiskError(code)
        for category, groups in config["groups"].items():
            if not isinstance(groups,dict) or not groups or abs(sum(number(v,0,1,code) for v in groups.values())-1)>1e-9:
                raise RiskError(code)
            if any(v<=0 for v in groups.values()):
                raise RiskError(code)
        bands=config["severity"]
        if [b["name"] for b in bands] != ["VERY_LOW","LOW","MEDIUM","HIGH","CRITICAL"]:
            raise RiskError(code)
        bounds=[number(b["minimum"],0,100,code) for b in bands]
        if bounds[0]!=0 or bounds!=sorted(set(bounds)):
            raise RiskError(code)
        ids=set()
        for signal in config["signals"]:
            allowed={"id","category","group","field","formula","maximum","quality","reason","low","high","status_values"}
            if set(signal)-allowed or not allowed-{"low","high","status_values"} <= set(signal):
                raise RiskError(code)
            if signal["id"] in ids or signal["category"] not in CATEGORIES or signal["group"] not in config["groups"][signal["category"]] or signal["formula"] not in FORMULAS:
                raise RiskError(code)
            ids.add(signal["id"])
            for field in ("id","field","reason"):
                if not isinstance(signal[field],str) or not signal[field] or len(signal[field])>512:
                    raise RiskError(code)
            number(signal["maximum"],0,1,code); number(signal["quality"],0,1,code)
            if signal["formula"] in {"ramp","inverse_ramp"} and not number(signal["high"],0,None,code)>number(signal["low"],0,None,code):
                raise RiskError(code)
            if signal["formula"]=="status":
                if set(signal["status_values"])!={"SAFE","SUSPICIOUS","MALICIOUS"}:
                    raise RiskError(code)
                for value in signal["status_values"].values():
                    number(value,0,1,code)
        if ids != {
            "url.ip_host","url.at_authority","url.idn","url.typosquatting","url.lure_keywords","url.entropy","url.length",
            "domain.young","dns.restricted","tls.invalid","reputation.provider","html.external_credentials",
            "html.script_obfuscation","html.external_iframe","content.urgency","content.credentials","content.financial","brand.mismatch","ml.phishing"}:
            raise RiskError(code)
        confidence=config["confidence"]
        if set(confidence)!={"coverage","quality","agreement","model","contradiction_penalty"}:
            raise RiskError(code)
        if abs(sum(number(confidence[k],0,1,code) for k in ("coverage","quality","agreement","model"))-1)>1e-9:
            raise RiskError(code)
        number(confidence["contradiction_penalty"],0,100,code)
        required={"legitimate_max_risk","suspicious_min_risk","phishing_min_risk","minimum_confidence_for_legitimate",
            "minimum_confidence_for_phishing","minimum_coverage_for_legitimate","minimum_coverage_for_phishing",
            "minimum_phishing_sources","alert_min_normalized","high_ml_probability","low_ml_probability","minimum_provider_confidence"}
        verdict=config["verdict"]
        if set(verdict)!=required:
            raise RiskError("VERDICT_CONFIGURATION_ERROR")
        for key,value in verdict.items():
            number(value,0,1 if key in {"alert_min_normalized","high_ml_probability","low_ml_probability","minimum_provider_confidence"} else 100,"VERDICT_CONFIGURATION_ERROR")
        if not verdict["legitimate_max_risk"]<verdict["suspicious_min_risk"]<verdict["phishing_min_risk"]:
            raise RiskError("VERDICT_CONFIGURATION_ERROR")
        if not 0<verdict["low_ml_probability"]<verdict["high_ml_probability"]<1 or verdict["minimum_phishing_sources"]<2:
            raise RiskError("VERDICT_CONFIGURATION_ERROR")
        if type(verdict["minimum_phishing_sources"]) is not int or verdict["minimum_phishing_sources"]>3:
            raise RiskError("VERDICT_CONFIGURATION_ERROR")
        if set(config["floors"])!={"corroborated_credential_harvesting","confirmed_reputation_and_harvesting","model_and_corroborated_harvesting"}:
            raise RiskError(code)
        for value in config["floors"].values():
            number(value,0,100,code)
        if set(config["evidence"])!={"minimum_normalized","top_k"}:
            raise RiskError(code)
        number(config["evidence"]["minimum_normalized"],0,1,code)
        if type(config["evidence"]["top_k"]) is not int or not 1<=config["evidence"]["top_k"]<=10:
            raise RiskError(code)
        return config
    except RiskError:
        raise
    except (KeyError,TypeError,ValueError,OverflowError):
        raise RiskError(code) from None

def load_config(path=DEFAULT_PATH):
    try:
        path=Path(path)
        if path.stat().st_size>65536:
            raise RiskError("SCORING_CONFIGURATION_ERROR")
        return validate_config(json.loads(path.read_text(encoding="utf8"), object_pairs_hook=unique_object))
    except RiskError:
        raise
    except (OSError,ValueError):
        raise RiskError("SCORING_CONFIGURATION_ERROR") from None

def unique_object(pairs):
    output={}
    for key,value in pairs:
        if key in output:
            raise RiskError("SCORING_CONFIGURATION_ERROR")
        output[key]=value
    return output

def config_digest(config):
    return hashlib.sha256(json.dumps(config,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
