"""The replay-cache seam and a single-node in-memory reference."""

from __future__ import annotations

import abc
import threading
from typing import Dict, Tuple


class ReplayCache(abc.ABC):
    """Atomically test for a previously seen (key_id, nonce) and record if new."""

    @abc.abstractmethod
    def check_and_remember(self, key_id: str, nonce: str, now_unix: int) -> bool:
        """Return True if fresh (and record it), False if already seen."""
        ...


class InMemoryReplayCache(ReplayCache):
    """In-memory TTL cache, bounded by the window. Per-process only."""

    def __init__(self, window_secs: int) -> None:
        self._window = window_secs
        self._lock = threading.Lock()
        self._seen: Dict[Tuple[str, str], int] = {}
        # Wall-clock second of the last full sweep, so the O(n) sweep is
        # amortized over a second of traffic instead of paid per request.
        self._last_prune: int | None = None

    def check_and_remember(self, key_id: str, nonce: str, now_unix: int) -> bool:
        with self._lock:
            # Sweep at most once per second: at R req/s that is O(1) amortized
            # per request rather than O(window * R). Letting an expired entry
            # linger for up to a second cannot cause a false accept (a stale
            # entry rejects, never admits); the bound becomes (window + 1)
            # seconds of traffic.
            if self._last_prune is None or now_unix > self._last_prune:
                self._seen = {k: v for k, v in self._seen.items() if v > now_unix}
                self._last_prune = now_unix
            key = (key_id, nonce)
            if key in self._seen:
                return False
            self._seen[key] = now_unix + self._window
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)
