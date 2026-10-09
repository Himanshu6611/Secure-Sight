"""Runtime secret-file support; never prints paths or secret values."""
import os
from pathlib import Path


def runtime_secret(name):
    direct, filename = os.getenv(name), os.getenv(name + "_FILE")
    if direct and filename:
        raise ValueError("Conflicting runtime secret configuration")
    if not filename:
        return direct
    try:
        path = Path(filename)
        if not path.is_file() or path.stat().st_size > 8192:
            raise ValueError()
        value = path.read_text(encoding="utf8").strip()
        if not value or "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError()
        return value
    except (OSError, ValueError, UnicodeError):
        raise ValueError("Runtime secret file unavailable or invalid") from None
