"""Bounded per-provider-origin breaker; never turns unavailable evidence into safe."""
from collections import OrderedDict
from contextlib import contextmanager
import threading
import time
from urllib.parse import urlsplit


class ProviderUnavailable(ValueError):
    pass


class ProviderCircuit:
    def __init__(self, failures=3, cooldown=30, max_entries=128):
        self.failures, self.cooldown, self.max_entries = failures, cooldown, max_entries
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def clear(self):
        with self.lock:
            self.entries.clear()

    @contextmanager
    def attempt(self, url):
        parsed = urlsplit(url)
        key = (parsed.scheme, parsed.hostname, parsed.port)
        with self.lock:
            state = self.entries.get(key, {"failures": 0, "retry_at": 0, "probe": False})
            if state["retry_at"] > time.monotonic() or state["probe"]:
                raise ProviderUnavailable("Provider circuit unavailable")
            if state["retry_at"]:
                state["probe"] = True
            self.entries[key] = state
            self.entries.move_to_end(key)
            while len(self.entries) > self.max_entries:
                self.entries.popitem(last=False)
        try:
            yield
        except Exception:
            with self.lock:
                state["failures"] += 1
                state["probe"] = False
                if state["failures"] >= self.failures:
                    state["retry_at"] = time.monotonic() + self.cooldown
            raise
        else:
            with self.lock:
                state.update(failures=0, retry_at=0, probe=False)


PROVIDER_CIRCUIT = ProviderCircuit()
