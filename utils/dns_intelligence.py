"""Bounded DNS queries without process-global socket settings."""
import ipaddress
import time
import dns.exception
import dns.resolver
from app.security.urls import public_ip, InvalidURL


def classify_ip_address(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return "INVALID"
    for attr, name in [("is_loopback", "LOOPBACK"), ("is_link_local", "LINK_LOCAL"),
                       ("is_multicast", "MULTICAST"), ("is_private", "PRIVATE")]:
        if getattr(address, attr):
            return name
    try:
        public_ip(value)
        return "PUBLIC"
    except InvalidURL:
        return "PRIVATE"


def is_ssrf_safe_ip(value):
    return classify_ip_address(value) == "PUBLIC"


def resolve_dns(domain, timeout=2.0):
    result = dict(status="INVALID_DOMAIN", resolved_ips=[], ipv4_addresses=[], ipv6_addresses=[],
                  ip_categories=[], has_a_record=False, has_aaaa_record=False, has_private_ip=False,
                  is_ssrf_safe=False, resolved_ip_count=0, records={}, record_states={})
    if not isinstance(domain, str) or not domain.strip():
        return result
    domain = domain.strip().rstrip(".")
    try:
        literal = str(ipaddress.ip_address(domain))
    except ValueError:
        literal = None
    if literal:
        result["resolved_ips"] = [literal]
        result["status"] = "SUCCESS"
    else:
        deadline = time.monotonic() + min(max(timeout, .01), 5)
        result["status"] = "SUCCESS"
        for record in ("A", "AAAA", "CNAME", "MX", "NS"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result["record_states"][record] = "TIMEOUT"
                if not result["resolved_ips"]:
                    result["status"] = "DNS_TIMEOUT"
                continue
            try:
                answer = dns.resolver.resolve(domain + ".", record, lifetime=remaining, search=False)
                values = [str(item) for item in answer]
                result["records"][record] = values
                result["record_states"][record] = "AVAILABLE"
                if record in {"A", "AAAA"}:
                    result["resolved_ips"].extend(values)
            except dns.resolver.NXDOMAIN:
                result["status"] = "DOMAIN_NOT_FOUND"
                break
            except dns.resolver.NoAnswer:
                result["record_states"][record] = "NO_RECORD"
            except dns.exception.Timeout:
                result["record_states"][record] = "TIMEOUT"
                if not result["resolved_ips"]:
                    result["status"] = "DNS_TIMEOUT"
            except dns.exception.DNSException:
                result["record_states"][record] = "ERROR"
                if not result["resolved_ips"]:
                    result["status"] = "DNS_PROVIDER_ERROR"
        if not result["resolved_ips"] and result["status"] == "SUCCESS":
            result["status"] = "DOMAIN_NOT_FOUND"
    ips = list(dict.fromkeys(result["resolved_ips"]))
    result["resolved_ips"] = ips
    result["ipv4_addresses"] = [i for i in ips if ":" not in i]
    result["ipv6_addresses"] = [i for i in ips if ":" in i]
    result["ip_categories"] = [classify_ip_address(i) for i in ips]
    result.update(has_a_record=bool(result["ipv4_addresses"]), has_aaaa_record=bool(result["ipv6_addresses"]),
                  has_private_ip=any(c != "PUBLIC" for c in result["ip_categories"]), resolved_ip_count=len(ips),
                  is_ssrf_safe=bool(ips) and all(is_ssrf_safe_ip(i) for i in ips))
    return result
