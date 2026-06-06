"""Tier 1: HMAC-SHA256 authentication + integrity, and timestamp freshness."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import List


def sign(key: bytes, canonical: str) -> str:
    """Lowercase-hex HMAC-SHA256 of `canonical` under `key`."""
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(key: bytes, canonical: str, provided_hex: str) -> bool:
    """Constant-time verification of a lowercase-hex signature."""
    try:
        provided = bytes.fromhex(provided_hex)
    except ValueError:
        return False
    if len(provided) != 32:
        return False
    expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)


def verify_any(keys: List[bytes], canonical: str, provided_hex: str) -> bool:
    """Verify against any candidate key (rotation overlap window)."""
    ok = False
    for k in keys:
        if verify(k, canonical, provided_hex):
            ok = True  # no early-out
    return ok


def parse_rfc3339_utc(iso: str) -> int:
    """Parse `YYYY-MM-DDTHH:MM:SSZ` to Unix seconds. Raises ValueError."""
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def check_freshness(timestamp_iso: str, now_unix: int, window_secs: int) -> bool:
    """True iff `timestamp_iso` is within +/- window_secs of now_unix."""
    try:
        ts = parse_rfc3339_utc(timestamp_iso)
    except ValueError:
        return False
    return abs(now_unix - ts) <= window_secs
