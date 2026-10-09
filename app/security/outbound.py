"""Bounded DNS and pinned sockets. No environment proxies or redirect following."""
import ipaddress
import socket
import ssl
import time
from urllib.parse import urlsplit

import dns.resolver
import urllib3

from .urls import InvalidURL, public_ip, validate_url


def pinned_pool(url, addresses=None, timeout=3.0):
    """No hostname resolution/proxy delegation after address validation."""
    parsed = urlsplit(validate_url(url))
    addresses = addresses if addresses is not None else resolve_public(parsed.hostname, min(timeout, 2.0))
    if not addresses:
        raise OSError("DNS unavailable")
    validated = [public_ip(address) for address in addresses]
    args = dict(host=validated[0], port=parsed.port or (443 if parsed.scheme == "https" else 80),
                timeout=urllib3.Timeout(total=timeout, connect=min(timeout, 2.0), read=timeout), maxsize=1)
    if parsed.scheme == "https":
        pool = urllib3.HTTPSConnectionPool(**args, cert_reqs=ssl.CERT_REQUIRED,
                                          server_hostname=parsed.hostname, assert_hostname=parsed.hostname)
    else:
        pool = urllib3.HTTPConnectionPool(**args)
    return parsed, pool


def resolve_public(host, timeout=2.0):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        addresses = []
        deadline = time.monotonic() + timeout
        for record in ("A", "AAAA"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("DNS deadline exceeded")
            try:
                answer = dns.resolver.resolve(host + ".", record, lifetime=remaining, search=False)
                addresses.extend(str(item) for item in answer)
            except dns.resolver.NoAnswer:
                continue
        if not addresses:
            raise OSError("No address found")
    else:
        addresses = [host]
    # Reject mixed public/private answers; connect only to one validated literal.
    return [public_ip(address) for address in addresses]


def safe_head(url):
    parsed = urlsplit(validate_url(url))
    parsed, pool = pinned_pool(url, resolve_public(parsed.hostname), timeout=2)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        response = pool.urlopen("HEAD", path, headers={"Host": parsed.netloc, "User-Agent": "SecureSight/1.0"},
                                redirect=False, retries=False, preload_content=False)
        try:
            return 200 <= response.status < 400
        finally:
            response.close()
    finally:
        pool.close()


def whois_text(domain, timeout=6.0):
    """IANA then one registry referral, public pinned addresses, bounded response."""
    parsed_domain = urlsplit(validate_url("https://" + domain))
    if parsed_domain.path or parsed_domain.query or parsed_domain.fragment or parsed_domain.port:
        raise InvalidURL()
    domain = parsed_domain.hostname
    deadline = time.monotonic() + timeout
    server = "whois.iana.org"
    text = ""
    for hop in range(2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("WHOIS deadline exceeded")
        host = urlsplit(validate_url("https://" + server)).hostname
        address = resolve_public(host, min(2.0, remaining))[0]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("WHOIS deadline exceeded")
        with socket.create_connection((address, 43), timeout=min(2, remaining)) as connection:
            query = domain.rsplit(".", 1)[-1] if hop == 0 else domain
            connection.sendall((query + "\r\n").encode("ascii"))
            payload = bytearray()
            while len(payload) < 65536:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("WHOIS deadline exceeded")
                connection.settimeout(min(2, remaining))
                chunk = connection.recv(min(4096, 65536 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
        text = payload.decode("utf-8", errors="replace")
        referral = next((line.split(":", 1)[1].strip() for line in text.splitlines()
                         if line.lower().startswith(("refer:", "whois:"))), None)
        if not referral:
            # IANA dates describe the TLD, not the submitted domain.
            return "" if hop == 0 else text
        server = referral
    return text
