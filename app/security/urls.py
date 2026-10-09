"""Strict URL syntax and globally routable address policy."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit, unquote

from werkzeug.exceptions import BadRequest


class InvalidURL(BadRequest):
    description = "The provided URL is invalid or targets a restricted address."


def public_ip(value):
    address = ipaddress.ip_address(value)
    # Block translation/tunnelling addresses as well as ordinary special ranges.
    if (not address.is_global or address.is_multicast or
        isinstance(address, ipaddress.IPv6Address) and
        (address.ipv4_mapped or address.sixtofour or address.teredo or
         address in ipaddress.ip_network("64:ff9b::/96") or
         address in ipaddress.ip_network("64:ff9b:1::/48"))):
        raise InvalidURL()
    return str(address)


def validate_url(value, max_length=2048):
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise InvalidURL()
    # Reject parser ambiguity, control characters, bad escapes and raw HTML.
    if any(ord(c) <= 32 or ord(c) == 127 or c in '\\<>"' for c in value):
        raise InvalidURL()
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise InvalidURL()
    if any(ord(c) < 32 or ord(c) == 127 for c in unquote(value)):
        raise InvalidURL()
    # Retain support for bare domains, but never reinterpret an explicit scheme.
    if "://" not in value:
        if ":" in value or value.startswith("/"):
            raise InvalidURL()
        value = "http://" + value
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise InvalidURL()
        if parsed.port not in {None, 80, 443} or parsed.netloc.endswith(":"):
            raise InvalidURL()
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if "%" in host or len(host) > 253:
            raise InvalidURL()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if (len(labels) < 2 or host.endswith((".localhost", ".local", ".internal", ".home", ".lan")) or
                labels[-1].isdigit() or
                any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
                raise InvalidURL()
        else:
            public_ip(host)
        authority = f"[{host}]" if ":" in host else host
        if parsed.port:
            authority += f":{parsed.port}"
        normalized = urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, parsed.fragment))
        if len(normalized) > max_length:
            raise InvalidURL()
        return normalized
    except (ValueError, UnicodeError):
        raise InvalidURL() from None
