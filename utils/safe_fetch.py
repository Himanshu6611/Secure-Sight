"""Bounded static retrieval through the shared pinned outbound gateway."""
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit
import dns.exception
import dns.resolver
import urllib3
from app.security.urls import validate_url, InvalidURL
from app.security.outbound import pinned_pool, resolve_public
from app.behavior.config import load_config
from app.behavior.privacy import redact_url, normalize_destination
from utils.domain_extraction import extract_domain_components

BEHAVIOR_CONFIG = load_config()
MAX_RESPONSE_BYTES = min(BEHAVIOR_CONFIG["max_response_size_bytes"], BEHAVIOR_CONFIG["max_total_response_bytes"])
MAX_REDIRECTS = BEHAVIOR_CONFIG["max_redirects"]
DEFAULT_TIMEOUT = BEHAVIOR_CONFIG["total_timeout_seconds"]
ALLOWED_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}


def is_url_ssrf_safe(url):
    try:
        from urllib.parse import urlsplit
        resolve_public(urlsplit(validate_url(url)).hostname)
        return True
    except (OSError, ValueError, InvalidURL, dns.exception.DNSException):
        return False


def fetch_webpage_safely(url, max_bytes=MAX_RESPONSE_BYTES, max_redirects=MAX_REDIRECTS, timeout=DEFAULT_TIMEOUT,
                         allowed_domain=None, allowed_content_types=None, allowed_hostname=None):
    result = dict(status="FETCH_FAILED", final_url="", status_code=None, content_type=None,
                  tls_status=None, html_content=None, html_size=0, redirect_count=0, error_message=None,
                  redirect_chain=[], request_count=0, response_bytes=0, unique_ip_count=0, elapsed_ms=0.,
                  initial_url=redact_url(url), redirect_loop_detected=False)
    started = time.monotonic()
    if allowed_content_types is None:
        allowed_content_types = ALLOWED_CONTENT_TYPES
    elif not isinstance(allowed_content_types, (set, frozenset)) or not allowed_content_types or not allowed_content_types <= ALLOWED_CONTENT_TYPES | {"text/plain"}:
        raise ValueError("Invalid content type policy")
    addresses = set()
    def failed(status, message):
        result.update(status=status, error_message=message, elapsed_ms=round((time.monotonic()-started)*1000,3))
        return result
    try:
        current = validate_url(url)
        if allowed_domain is not None and extract_domain_components(current)["normalized_registrable_domain"] != allowed_domain:
            return failed("CRAWL_SCOPE_BLOCKED", "Destination is outside the crawl scope.")
        if allowed_hostname is not None and urlsplit(current).hostname != allowed_hostname:
            return failed("CRAWL_SCOPE_BLOCKED", "Destination is outside the robots hostname scope.")
    except InvalidURL:
        return failed("INVALID_URL", "Invalid or restricted target URL.")
    if type(max_bytes) is not int or type(max_redirects) is not int or type(timeout) not in (int, float) or not 0 < max_bytes <= MAX_RESPONSE_BYTES or not 0 <= max_redirects <= MAX_REDIRECTS or not 0 < timeout <= DEFAULT_TIMEOUT:
        return failed("INVALID_URL", "Invalid retrieval limits.")
    deadline = time.monotonic() + timeout
    visited = {normalize_destination(current)}
    for hop in range(max_redirects + 1):
        pool = response = None
        result.update(final_url=current)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return failed("TIMEOUT", "Retrieval deadline exceeded.")
            parsed, pool = pinned_pool(current, timeout=min(remaining, BEHAVIOR_CONFIG["request_timeout_seconds"]))
            if isinstance(pool.host, str):
                addresses.add(pool.host)
                result["unique_ip_count"] = len(addresses)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return failed("TIMEOUT", "Retrieval deadline exceeded.")
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            hop_started = time.monotonic()
            result["request_count"] += 1
            response = pool.urlopen("GET", path, headers={"Host": parsed.netloc,
                "User-Agent": "SecureSight-Scanner/5.1", "Accept-Encoding": "identity"},
                redirect=False, retries=False, preload_content=False,
                timeout=urllib3.Timeout(total=min(remaining, BEHAVIOR_CONFIG["request_timeout_seconds"]), connect=min(2, remaining), read=min(remaining, BEHAVIOR_CONFIG["request_timeout_seconds"])))
            result["status_code"] = response.status
            if result["redirect_chain"]:
                result["redirect_chain"][-1]["followed"] = True
            content_type = response.headers.get("Content-Type", "").lower()
            result["content_type"] = content_type
            if response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("Location")
                if not location:
                    return failed("FETCH_FAILED", "Redirect destination missing.")
                candidate = urljoin(current, location)
                destination = urlsplit(candidate)
                source_domain = extract_domain_components(current)
                record = dict(index=hop, source_url=redact_url(current), destination_url=redact_url(candidate),
                    source_domain=source_domain["normalized_registrable_domain"], destination_domain=None,
                    status_code=response.status, redirect_type="HTTP", elapsed_ms=round((time.monotonic()-hop_started)*1000,3),
                    timestamp_ms=round((time.monotonic()-started)*1000,3), followed=False)
                result["redirect_chain"].append(record)
                result["redirect_count"] = len(result["redirect_chain"])
                candidate = validate_url(candidate)
                target_domain = extract_domain_components(candidate)
                if allowed_domain is not None and target_domain["normalized_registrable_domain"] != allowed_domain:
                    return failed("CRAWL_SCOPE_BLOCKED", "Redirect is outside the crawl scope.")
                if allowed_hostname is not None and urlsplit(candidate).hostname != allowed_hostname:
                    return failed("CRAWL_SCOPE_BLOCKED", "Redirect is outside the robots hostname scope.")
                record.update(destination_domain=target_domain["normalized_registrable_domain"],
                    same_domain=source_domain["normalized_registrable_domain"] == target_domain["normalized_registrable_domain"],
                    subdomain_changed=source_domain["normalized_hostname"] != target_domain["normalized_hostname"],
                    cross_tld=source_domain["tld"] != target_domain["tld"],
                    http_to_https=parsed.scheme == "http" and destination.scheme == "https",
                    https_to_http=parsed.scheme == "https" and destination.scheme == "http",
                    port_changed=(parsed.port or (443 if parsed.scheme == "https" else 80)) != (destination.port or (443 if destination.scheme == "https" else 80)))
                normalized = normalize_destination(candidate)
                if normalized in visited:
                    result["redirect_loop_detected"] = True
                    return failed("REDIRECT_LOOP", "Redirect loop detected.")
                if hop == max_redirects:
                    return failed("REDIRECT_LIMIT_EXCEEDED", "Redirect limit exceeded.")
                visited.add(normalized)
                current = candidate
                continue
            if not 200 <= response.status < 300:
                return failed("HTTP_ERROR", "Destination returned an unsuccessful HTTP status.")
            if content_type.split(";", 1)[0].strip() not in allowed_content_types:
                return failed("CONTENT_TYPE_UNSUPPORTED", "Expected an HTML content type.")
            if response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
                return failed("CONTENT_TYPE_UNSUPPORTED", "Compressed responses are not accepted.")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                return failed("RESOURCE_LIMIT_EXCEEDED", "Response body exceeds the byte limit.")
            payload = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                remaining = min(remaining, hop_started + BEHAVIOR_CONFIG["request_timeout_seconds"] - time.monotonic())
                if remaining <= 0:
                    return failed("TIMEOUT", "Retrieval deadline exceeded.")
                connection = getattr(response, "connection", None)
                if connection is not None and getattr(connection, "sock", None) is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, max_bytes + 1 - len(payload)), decode_content=False)
                if not chunk:
                    break
                payload.extend(chunk)
                result["response_bytes"] = len(payload)
                if len(payload) > max_bytes:
                    return failed("RESOURCE_LIMIT_EXCEEDED", "Response body exceeds the byte limit.")
            result.update(status="SUCCESS", html_content=payload.decode("utf8", errors="replace"),
                          html_size=len(payload), tls_status="valid" if parsed.scheme == "https" else "http",
                          elapsed_ms=round((time.monotonic()-started)*1000,3))
            return result
        except InvalidURL:
            return failed("SSRF_BLOCKED", "Destination violates the outbound address policy.")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, OSError) as exc:
            if isinstance(exc, (TimeoutError, socket.timeout, ssl.SSLError)):
                return failed("TIMEOUT" if not isinstance(exc, ssl.SSLError) else "TLS_FAILED", "Retrieval could not complete within transport limits.")
            return failed("DNS_FAILED", "Destination DNS is unavailable.")
        except (TimeoutError, socket.timeout, dns.exception.Timeout, urllib3.exceptions.TimeoutError):
            return failed("TIMEOUT", "Retrieval deadline exceeded.")
        except (ssl.SSLError, urllib3.exceptions.SSLError):
            return failed("TLS_FAILED", "TLS verification failed.")
        except Exception:
            return failed("FETCH_FAILED", "Unable to retrieve the webpage.")
        finally:
            if response is not None:
                response.close()
            if pool is not None:
                pool.close()
    return failed("FETCH_FAILED", "Unable to retrieve the webpage.")
