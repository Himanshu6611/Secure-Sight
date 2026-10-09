"""Verify signatures; never trust receiver claims in an uploaded message."""
import re
import time
from email import policy
from email.parser import BytesParser
from .headers import domain, relationship, registrable

STATES = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


def tags(value):
    result = {}
    for item in str(value).split(";"):
        if "=" in item:
            key, val = item.split("=", 1)
            key = key.strip().lower()
            if key in result:
                raise ValueError("Duplicate authentication tag")
            result[key] = val.strip()[:8192]
    return result


class DNSBudget:
    def __init__(self):
        self.deadline, self.queries = time.monotonic() + 6, 0
        self.failed = False

    def __call__(self, name, timeout=1):
        import dns.resolver
        name = name.decode("ascii") if isinstance(name, bytes) else name
        name = name.rstrip(".")
        if len(name) > 253 or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", label) for label in name.split(".")):
            raise ValueError("Invalid authentication DNS name")
        suffix = name.split("._domainkey.", 1)[-1] if "._domainkey." in name else name.removeprefix("_dmarc.")
        if not domain(suffix):
            raise ValueError("Restricted authentication DNS domain")
        self.queries += 1
        remaining = self.deadline - time.monotonic()
        if self.queries > 8 or remaining <= 0:
            self.failed = True
            raise TimeoutError("Authentication DNS budget")
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=min(1, remaining), search=False)
            records = [b"".join(answer.strings) for answer in answers]
            if len(records) > 8 or sum(map(len, records)) > 16384:
                raise ValueError("Authentication record limit")
            return records[0] if len(records) == 1 else None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception:
            self.failed = True
            raise


def analyze(raw, headers, dns_lookup=None):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    claims = []
    for value in message.get_all("Authentication-Results", [])[:8]:
        # Claims remain untrusted even when authserv-id looks like a known MTA.
        try:
            import authres
            parsed_header = authres.AuthenticationResultsHeader.parse("Authentication-Results: " + str(value))
            for record in parsed_header.results[:8]:
                if record.method in {"spf", "dkim", "dmarc", "arc"}:
                    claims.append({"method": record.method, "result": record.result.upper() if record.result in STATES else "UNKNOWN",
                        "authserv_id": str(parsed_header.authserv_id)[:128], "trust": "UNTRUSTED_UPLOAD",
                        "claimed_domains": [domain(str(p.value).rsplit("@", 1)[-1]) for p in record.properties
                            if p.name in {"mailfrom", "d", "from"}][:4]})
        except Exception:
            claims.append({"method": "UNKNOWN", "result": "PERMERROR", "trust": "UNTRUSTED_UPLOAD"})
    lookup = dns_lookup or DNSBudget()
    output = {"version": "11.0", "claims": claims[:32], "claims_trusted": False,
        "spf": {"result": "UNAVAILABLE", "evaluated_domain": None, "reason": "TRUSTED_SMTP_PEER_AND_ENVELOPE_UNAVAILABLE"},
        "dkim": {"result": "NONE", "signatures": []},
        "dmarc": {"result": "UNAVAILABLE", "domain": headers["from_domain"], "policy": None, "alignment": "UNKNOWN"},
        "arc": {"result": "NONE", "seal_count": len(message.get_all("ARC-Seal", [])), "chain_trusted": False},
        "dnssec_verified": False, "authentication_is_safety_proof": False}
    try:
        import dkim
    except ImportError:
        output["dkim"]["result"] = output["arc"]["result"] = "UNAVAILABLE"
        return output
    signatures = message.get_all("DKIM-Signature", [])
    output["arc"]["seals"] = []
    for seal in message.get_all("ARC-Seal", [])[:4]:
        try:
            parsed = tags(seal)
            output["arc"]["seals"].append({"instance": parsed.get("i"), "domain": domain(parsed.get("d", "")),
                "selector": parsed.get("s"), "claimed_chain_validation": parsed.get("cv"), "timestamp": parsed.get("t")})
        except ValueError:
            output["arc"]["seals"].append({"status": "MALFORMED"})
    verifier = dkim.DKIM(raw, minkey=2048) if signatures else None
    for index, value in enumerate(signatures[:2]):
        record = {"result": "PERMERROR", "domain": None, "selector": None, "algorithm": None,
                  "canonicalization": None, "alignment": "UNKNOWN", "body_length_limited": None}
        try:
            parsed = tags(value)
            signing_domain = domain(parsed.get("d", ""))
            selector = parsed.get("s", "")
            record.update(domain=signing_domain, selector=selector[:63], algorithm=parsed.get("a"),
                canonicalization=parsed.get("c", "simple/simple"), body_length_limited="l" in parsed,
                signing_timestamp=parsed.get("t"), expiration_timestamp=parsed.get("x"))
            if not signing_domain or not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", selector) or parsed.get("a") != "rsa-sha256":
                raise ValueError("Unsupported or malformed DKIM")
            record["result"] = "PASS" if verifier.verify(idx=index, dnsfunc=lookup) else "FAIL"
            if getattr(lookup, "failed", False):
                record["result"] = "TEMPERROR"
            record["alignment"] = relationship(headers["from_domain"], signing_domain)
        except Exception:
            record["result"] = "TEMPERROR" if getattr(lookup, "failed", False) else "PERMERROR"
        output["dkim"]["signatures"].append(record)
    states = [r["result"] for r in output["dkim"]["signatures"]]
    output["dkim"]["result"] = "PASS" if "PASS" in states else "TEMPERROR" if "TEMPERROR" in states else states[0] if states else "NONE"
    output["dkim"]["signature_limit_reached"] = len(signatures) > 2
    if output["arc"]["seal_count"]:
        if output["arc"]["seal_count"] > 4:
            output["arc"]["result"] = "PERMERROR"
        else:
            try:
                state, details, _ = dkim.arc_verify(raw, dnsfunc=lookup, minkey=2048, timeout=1)
                state = state.decode() if isinstance(state, bytes) else str(state)
                output["arc"].update(result=state.upper() if state.lower() in {"pass", "fail", "none"} else "UNAVAILABLE",
                    verified_sets=len(details), chain_trusted=False)
            except Exception:
                output["arc"]["result"] = "TEMPERROR" if getattr(lookup, "failed", False) else "PERMERROR"
    from_domain = headers["from_domain"]
    if from_domain:
        try:
            record = lookup(("_dmarc." + from_domain).encode())
            if not record and registrable(from_domain) != from_domain:
                record = lookup(("_dmarc." + registrable(from_domain)).encode())
            if record:
                parsed = tags(record.decode("ascii"))
                if parsed.get("v") != "DMARC1" or parsed.get("p") not in {"none", "quarantine", "reject"} or parsed.get("adkim", "r") not in {"r", "s"}:
                    raise ValueError("Invalid DMARC policy")
                aligned = any(r["result"] == "PASS" and (r["alignment"] == "ALIGNED" or
                    parsed.get("adkim", "r") == "r" and r["alignment"] == "PARTIALLY_ALIGNED") for r in output["dkim"]["signatures"])
                output["dmarc"].update(policy=parsed["p"], alignment="ALIGNED" if aligned else "UNKNOWN",
                    result="PASS" if aligned else "UNAVAILABLE", reason="ALIGNED_VERIFIED_DKIM" if aligned else "SPF_PATH_UNAVAILABLE")
            else:
                output["dmarc"].update(result="NONE", reason="POLICY_NOT_FOUND")
        except Exception:
            output["dmarc"].update(result="TEMPERROR" if getattr(lookup, "failed", False) else "PERMERROR")
    output["dns_queries"] = getattr(lookup, "queries", None)
    return output
