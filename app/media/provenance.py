"""Read original Content Credentials with network retrieval disabled."""
import io
import json
import os


def _public_claims(store):
    active = store.get("active_manifest")
    manifest = (store.get("manifests") or {}).get(active, {}) if isinstance(active, str) else {}
    assertions = manifest.get("assertions", []) if isinstance(manifest, dict) else []
    claims = []
    if not isinstance(assertions, list):
        return claims
    for assertion in assertions[:16]:
        if not isinstance(assertion, dict) or not str(assertion.get("label", "")).startswith("c2pa.actions"):
            continue
        data = assertion.get("data")
        actions = data.get("actions", []) if isinstance(data, dict) else []
        if not isinstance(actions, list):
            continue
        for action in actions[:16 - len(claims)]:
            if not isinstance(action, dict):
                continue
            item = {}
            for source, destination, limit in (("action", "action", 80),
                    ("digitalSourceType", "digital_source_type", 256), ("when", "declared_when", 80)):
                value = action.get(source)
                if isinstance(value, str) and value.strip():
                    item[destination] = value.strip()[:limit]
            # C2PA softwareAgent is a signed-manifest declaration, not an
            # independently verified claim about the depicted content.
            agent = action.get("softwareAgent")
            if isinstance(agent, str) and agent.strip():
                item["software_agent"] = agent.strip()[:120]
            elif isinstance(agent, dict):
                name = agent.get("name")
                version = agent.get("version")
                if isinstance(name, str) and name.strip():
                    item["software_agent"] = name.strip()[:100]
                    if isinstance(version, str) and version.strip():
                        item["software_agent_version"] = version.strip()[:32]
            if item:
                claims.append(item)
    return claims


def analyze(data, mime, trusted_anchors=None):
    result = {"status": "UNSUPPORTED", "signature_valid": None, "trusted": None,
              "network_fetch": False, "claims_are_truth": False}
    try:
        from c2pa import Context, Reader
    except ImportError:
        return result
    try:
        settings = {"verify": {"verify_after_reading": True, "verify_trust": True,
                "verify_timestamp_trust": True, "remote_manifest_fetch": False, "ocsp_fetch": False}}
        if trusted_anchors is None and os.environ.get("C2PA_TRUST_ANCHORS_FILE"):
            with open(os.environ["C2PA_TRUST_ANCHORS_FILE"], "r", encoding="ascii") as anchors:
                trusted_anchors = anchors.read(65537)
        if trusted_anchors:
            if len(trusted_anchors) > 65536 or "-----BEGIN CERTIFICATE-----" not in trusted_anchors:
                raise ValueError("Invalid operator trust configuration")
            settings["trust"] = {"user_anchors": trusted_anchors}
        with Context.from_dict(settings) as context:
            with Reader(mime, io.BytesIO(data), context=context) as reader:
                store = json.loads(reader.json())
                if not store.get("active_manifest"):
                    return {**result, "status": "ABSENT", "claims": [], "claims_available": True}
                state = reader.get_validation_state()
                validation = reader.get_validation_results()
                # The SDK exposes Invalid/Valid/Trusted states; untrusted signatures
                # must never be reported as cryptographically trusted provenance.
                state = str(state).split(".")[-1].lower()
                status = "INVALID" if state == "invalid" else "VALID" if state == "trusted" else "PRESENT_UNVERIFIED"
                return {**result, "status": status, "signature_valid": True if state in {"valid", "trusted"} else False if status == "INVALID" else None,
                        "trusted": status == "VALID", "validation_state": state,
                        "revocation_status": "NOT_FETCHED_OFFLINE",
                        "validation_report_available": bool(validation),
                        "claims": _public_claims(store), "claims_available": True}
    except Exception as exc:
        name = str(exc).lower()
        absent = "manifestnotfound" in name or "manifest not found" in name or "jumbfnotfound" in name
        return {**result, "status": "ABSENT" if absent else "ERROR", "claims": [],
                "claims_available": False, "error_code": None if absent else "PROVENANCE_UNAVAILABLE"}
