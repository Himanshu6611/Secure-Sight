"""Adapt actual P2–5 outputs without fetching, parsing or loading models."""
from .normalization import normalize, number, boolean
from .schemas import Signal, RiskError
from .brand import brand_observation

def mapping(value):
    if not isinstance(value,dict):
        raise RiskError("RISK_INPUT_INVALID")
    return value

def state(status, available):
    if status in available:
        return "AVAILABLE"
    if status and "TIMEOUT" in status:
        return "TIMEOUT"
    if status and ("FAILED" in status or "ERROR" in status or "INVALID" in status):
        return "ERROR"
    return "UNAVAILABLE"

def collect_signals(context, config):
    if context is None:
        raise RiskError("MISSING_ANALYSIS_CONTEXT")
    context=mapping(context)
    if set(context)-{"url_features","url_indicators","domain_intelligence","web_intelligence","ml_result","scheme","feature_schema_version","behavior_intelligence","brand_intelligence"}:
        raise RiskError("RISK_INPUT_INVALID")
    for key in ("url_features","domain_intelligence","web_intelligence","ml_result"):
        if key not in context:
            raise RiskError("MISSING_ANALYSIS_CONTEXT")
    url=dict(mapping(context["url_features"])); domain=mapping(context["domain_intelligence"])
    web=mapping(context["web_intelligence"]); ml=mapping(context["ml_result"])
    dns=mapping(domain.get("dns",{})); tls=mapping(domain.get("tls",{}))
    registration=mapping(domain.get("registration",{})); reputation=mapping(domain.get("reputation",{}))
    for result in (dns,tls,registration,reputation,web,ml):
        for key in ("status","reputation_status"):
            if key in result and not isinstance(result[key],str):
                raise RiskError("RISK_INPUT_INVALID")
    if context.get("scheme","https") not in {"http","https"}:
        raise RiskError("RISK_INPUT_INVALID")
    for value in (context.get("feature_schema_version"),ml.get("feature_schema_version"),ml.get("model_version")):
        if value is not None and (not isinstance(value,str) or len(value)>64):
            raise RiskError("RISK_INPUT_INVALID")
    # Validate every numeric feature that the classifier/DOM engines actually emit.
    # P2 uses -1 for a non-applicable brand distance on some host forms.
    # It is not a negative risk value, and is not used by this scoring policy.
    if url.get("min_brand_distance")==-1:
        url["min_brand_distance"]=None
    for values in (url, mapping(web.get("combined_web_features",{}))):
        if len(values)>200:
            raise RiskError("RISK_INPUT_INVALID")
        for value in values.values():
            if value is not None:
                if isinstance(value,bool):
                    continue
                number(value,0)
    web_values=web.get("combined_web_features",{})
    indicators=context.get("url_indicators")
    if indicators is not None:
        if not isinstance(indicators,list) or len(indicators)>100 or any(not isinstance(i,dict) for i in indicators):
            raise RiskError("RISK_INPUT_INVALID")
        url["authority_obfuscation"]=int(any(i.get("code")=="AT_SYMBOL_OBFUSCATION" for i in indicators))
    else:
        url["authority_obfuscation"]=0 if url.get("has_at_symbol")==0 else None
    if web.get("status")=="ANALYZED":
        forms=web.get("forms")
        if not isinstance(forms,list) or len(forms)>1000:
            raise RiskError("RISK_INPUT_INVALID")
        external=False
        for form in forms:
            form=mapping(form)
            is_external=boolean(form.get("is_external"))
            credential=boolean(form.get("is_credential_form"))
            external=bool(is_external and credential) or external
    else:
        external=None
    probability=ml.get("probability")
    if ml.get("status")=="OK":
        probability=number(probability,0,1)
    model_valid=(ml.get("status")=="OK" and ml.get("model_version") in config["model_versions"]
                 and ml.get("feature_schema_version") in config["feature_schema_versions"]
                 and context.get("feature_schema_version",ml.get("feature_schema_version"))==ml.get("feature_schema_version")
                 and ml.get("model_validated") is True)
    stages={
        "url":"AVAILABLE" if url and url.get("url_len",0)>0 and url.get("hostname_len",0)>0 else "UNAVAILABLE",
        "dns":state(dns.get("status"),{"SUCCESS"}),
        "tls":"NOT_APPLICABLE" if context.get("scheme")=="http" else state(tls.get("status"),{"VALID","EXPIRING_SOON","INVALID","EXPIRED"}),
        "registration":state(registration.get("status"),{"AVAILABLE","PARTIAL"}),
        "reputation":state(reputation.get("reputation_status"),{"SAFE","SUSPICIOUS","MALICIOUS"}),
        "html":state(web.get("status"),{"ANALYZED"}),
        "content":state(web.get("status"),{"ANALYZED"}) if web_values else "UNAVAILABLE",
        "ml":"AVAILABLE" if model_valid else "ERROR" if ml.get("status")=="OK" else state(ml.get("status"),set()),
    }
    if registration.get("domain_age_days") is None:
        stages["registration"]="UNAVAILABLE"
    if stages["content"]=="AVAILABLE" and any(web_values.get(key) is None for key in (
            "urgency_score","credential_score","financial_language_score","brand_domain_mismatch")):
        stages["content"]="PARTIAL"
    providers=reputation.get("providers",[])
    if not isinstance(providers,list) or len(providers)>100:
        raise RiskError("RISK_INPUT_INVALID")
    provider_quality=None
    known_quality=[]
    for provider in providers:
        provider=mapping(provider)
        quality=number(provider.get("confidence",0),0,1)
        if provider.get("status")==reputation.get("reputation_status"):
            known_quality.append(quality)
    if known_quality:
        provider_quality=max(known_quality) if reputation.get("reputation_status")!="SAFE" else min(known_quality)
    if reputation.get("reputation_status")=="SAFE" and any(p.get("status")!="SAFE" for p in providers):
        provider_quality=None
    # Claimed aggregate SAFE/MALICIOUS needs provider-level reliability evidence.
    if reputation.get("reputation_status") in {"SAFE","MALICIOUS"} and (provider_quality is None or provider_quality<config["verdict"]["minimum_provider_confidence"]):
        stages["reputation"]="UNAVAILABLE"
    sources={
        "url":(url,stages["url"],"phase_2"),
        "domain":(registration,stages["registration"],"phase_3_registration"),
        "dns":(dns,stages["dns"],"phase_3_dns"),
        "tls":(tls,stages["tls"],"phase_3_tls"),
        "reputation":(reputation,stages["reputation"],"phase_3_reputation"),
        "html":({**web_values,"external_credentials":external},stages["html"],"phase_4_static"),
        "content":(web_values,stages["content"],"phase_4_static"),
        "brand":(web_values,stages["content"],"phase_4_static"),
        "ml":(ml,stages["ml"],"phase_5"),
    }
    observed_brand = brand_observation(context)
    if observed_brand is not None:
        sources["brand"] = observed_brand
    signals=[]
    for definition in config["signals"]:
        category=definition["category"]
        source_key="dns" if definition["id"].startswith("dns.") else "tls" if definition["id"].startswith("tls.") else category
        values, availability, source=sources[source_key]
        value=values.get(definition["field"]) if availability in {"AVAILABLE","PARTIAL"} else None
        if value is not None and availability=="PARTIAL":
            availability="AVAILABLE"
        if value is None and availability in {"AVAILABLE","PARTIAL"}:
            availability="UNAVAILABLE"
        normalized=normalize(value,definition) if availability=="AVAILABLE" else None
        quality=definition["quality"]
        if category=="reputation" and provider_quality is not None:
            quality=min(quality,provider_quality)
        if category=="ml" and ml.get("calibration_method") not in {"sigmoid","isotonic"}:
            quality=0.
        if availability!="AVAILABLE":
            quality=0.
        severity="INFO" if not normalized else "HIGH" if normalized>=config["verdict"]["alert_min_normalized"] else "LOW"
        reason=definition["reason"] if normalized else (
            "No configured risk contribution was observed; this is not a safety guarantee." if availability=="AVAILABLE"
            else "This signal is unavailable or not applicable; no risk or safety conclusion was inferred.")
        signals.append(Signal(definition["id"],category.upper(),definition["group"],definition["id"].split(".",1)[1].replace("_"," "),
            value,normalized,config["groups"][category][definition["group"]],severity,source,quality,
            reason,availability))
    flags={
        "model_valid":model_valid,"model_calibrated":model_valid and ml.get("calibration_method") in {"sigmoid","isotonic"},
        "dns_safe":stages["dns"]=="AVAILABLE" and boolean(dns.get("is_ssrf_safe",False))==1,
        "essential_complete":stages["url"]=="AVAILABLE" and stages["dns"]=="AVAILABLE" and stages["html"]=="AVAILABLE" and model_valid,
        "observed_web":stages["html"]=="AVAILABLE",
        "tls_unsafe":tls.get("status") in {"INVALID","EXPIRED"},
        "reputation_suspicious":stages["reputation"]=="AVAILABLE" and reputation.get("reputation_status")=="SUSPICIOUS",
        "reputation_malicious":stages["reputation"]=="AVAILABLE" and reputation.get("reputation_status")=="MALICIOUS",
        "reputation_safe":stages["reputation"]=="AVAILABLE" and reputation.get("reputation_status")=="SAFE",
        "model_version":ml.get("model_version"),"feature_schema_version":context.get("feature_schema_version") or ml.get("feature_schema_version"),
        "ml_probability":probability if model_valid else None,
        "unconfirmed_external_credentials":bool(observed_brand is not None and external and (
            not context["brand_intelligence"].get("features", {}).get("official_auth_destination") or
            context["brand_intelligence"].get("features", {}).get("external_nonofficial_credentials"))),
    }
    return signals, stages, flags
