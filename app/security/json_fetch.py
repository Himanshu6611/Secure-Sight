"""Small JSON provider responses through the same public-IP pinned gateway.

No ambient proxies, cookies, authorization, compression, retries or auto redirects.
"""
import time
from urllib.parse import urljoin
import urllib3
from app.security.urls import validate_url
from app.security.outbound import pinned_pool
from app.security.json_policy import strict_loads
from app.security.circuit import PROVIDER_CIRCUIT


def fetch_json(url, deadline, max_bytes=131072):
    if type(max_bytes) is not int or not 0 < max_bytes <= 131072:
        raise ValueError("Invalid JSON response budget")
    current = validate_url(url)
    if current.startswith("http:"):
        raise ValueError("JSON providers require HTTPS")
    with PROVIDER_CIRCUIT.attempt(current):
        return _fetch_json(current, deadline, max_bytes)


def _fetch_json(url, deadline, max_bytes):
    response = pool = None
    current = validate_url(url)
    for hop in range(2):
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Provider deadline")
            parsed, pool = pinned_pool(current, timeout=min(remaining, 2))
            if parsed.scheme != "https":
                raise ValueError("JSON providers require HTTPS")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Provider deadline")
            path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
            response = pool.urlopen("GET", path, headers={"Host": parsed.netloc,
                "Accept": "application/rdap+json, application/json", "Accept-Encoding": "identity",
                "User-Agent": "SecureSight-Scanner/9"}, redirect=False, retries=False,
                preload_content=False, timeout=urllib3.Timeout(total=remaining, connect=min(remaining, 2), read=remaining))
            if response.status in {301, 302, 303, 307, 308}:
                if hop or not response.headers.get("Location"):
                    raise ValueError("Provider redirect limit")
                current = validate_url(urljoin(current, response.headers["Location"]))
                continue
            if response.status != 200:
                raise ValueError("Provider HTTP failure")
            if response.headers.get("Content-Type", "").split(";", 1)[0].lower().strip() not in {"application/json", "application/rdap+json"}:
                raise ValueError("Provider content type")
            if response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
                raise ValueError("Provider compression disabled")
            payload = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Provider deadline")
                connection = getattr(response, "connection", None)
                if connection and getattr(connection, "sock", None):
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, max_bytes + 1 - len(payload)), decode_content=False)
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > max_bytes:
                    raise ValueError("Provider response limit")
            data = strict_loads(payload)
            if not isinstance(data, dict):
                raise ValueError("Provider object required")
            return data
        finally:
            if response is not None:
                response.close()
                response = None
            if pool is not None:
                pool.close()
                pool = None
    raise ValueError("Provider retrieval incomplete")
