# utils/domain_cache.py
"""
utils/domain_cache.py
---------------------
Thread-safe Memory TTL Cache for SecureSight Phase 3.
Prevents redundant DNS, WHOIS, TLS, and Reputation lookups.
"""

import time
import threading
from collections import OrderedDict
from copy import deepcopy
from typing import Dict, Any, Optional


class TTLMemoryCache:
    """Thread-safe memory cache with TTL expiration."""

    def __init__(self, default_ttl: float = 300.0, max_entries: int = 512):
        self.default_ttl = default_ttl
        self.max_entries = max_entries
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached value if present and not expired."""
        with self._lock:
            if key not in self._cache:
                return None
            item = self._cache[key]
            if time.monotonic() > item["expires_at"]:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return deepcopy(item["value"])

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Store value in cache with TTL in seconds."""
        if ttl is None:
            ttl = self.default_ttl
        expires_at = time.monotonic() + min(ttl, self.default_ttl)
        with self._lock:
            for expired in [k for k, v in self._cache.items() if v['expires_at'] <= time.monotonic()]:
                del self._cache[expired]
            self._cache[key] = {
                "value": deepcopy(value),
                "expires_at": expires_at
            }
            self._cache.move_to_end(key)
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()


# Global domain intelligence cache instance
DOMAIN_INTELLIGENCE_CACHE = TTLMemoryCache(default_ttl=300.0)
