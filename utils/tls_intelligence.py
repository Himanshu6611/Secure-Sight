"""TLS connects only to a validated literal, preserving hostname verification."""
import socket
import ssl
import time
import datetime
from urllib.parse import urlsplit
from app.security.urls import validate_url, public_ip, InvalidURL
from app.security.outbound import resolve_public


def analyze_tls_certificate(hostname, port=443, timeout=2.0, resolved_ips=None):
    result = dict(status="UNAVAILABLE", certificate_present=False, certificate_valid=False,
                  days_until_expiry=None, issuer=None, subject=None, san=[], not_before=None,
                  not_after=None, error_message=None)
    try:
        if not hostname or port not in {80, 443}:
            raise InvalidURL()
        host = f"[{hostname}]" if ":" in hostname else hostname
        parsed = urlsplit(validate_url(f"https://{host}:{port}/"))
        deadline = time.monotonic() + timeout
        addresses = resolved_ips if resolved_ips is not None else resolve_public(parsed.hostname, timeout)
        addresses = [public_ip(ip) for ip in addresses]
        if not addresses:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        context = ssl.create_default_context()
        with socket.create_connection((addresses[0], port), timeout=remaining) as sock:
            sock.settimeout(max(.001, deadline - time.monotonic()))
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as secure:
                cert = secure.getpeercert()
        if not cert:
            return result
        until = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), datetime.timezone.utc)
        days = (until - datetime.datetime.now(datetime.timezone.utc)).days
        result.update(status="EXPIRING_SOON" if days <= 14 else "VALID", certificate_present=True,
                      certificate_valid=True, days_until_expiry=days, issuer=cert.get("issuer"),
                      subject=cert.get("subject"), san=list(cert.get("subjectAltName", [])),
                      not_before=cert.get("notBefore"), not_after=cert.get("notAfter"))
    except InvalidURL:
        result.update(status="SSRF_BLOCKED", error_message="Destination violates the outbound address policy.")
    except ssl.SSLError:
        result.update(status="INVALID", error_message="TLS certificate verification failed.")
    except (TimeoutError, socket.timeout):
        result["error_message"] = "TLS inspection timed out."
    except Exception:
        result["error_message"] = "TLS inspection unavailable."
    return result
