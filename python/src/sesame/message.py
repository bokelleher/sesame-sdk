"""SESAME header names, the error taxonomy (Appendix A.7), and header parsing."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Callable, Optional


class Header:
    VERSION = "X-SESAME-Version"
    KEY_ID = "X-SESAME-KeyId"
    TIMESTAMP = "X-SESAME-Timestamp"
    NONCE = "X-SESAME-Nonce"
    SIGNATURE = "X-SESAME-Signature"
    SCOPE = "X-SESAME-Scope"
    ENCRYPTED = "X-SESAME-Encrypted"
    ENC_KEY_ID = "X-SESAME-EncKeyId"
    IV = "X-SESAME-IV"


PROTOCOL_VERSION = "1.0"


class SesameErrorCode(enum.Enum):
    MISSING_HEADERS = "sesame_missing_headers"
    INVALID_VERSION = "sesame_invalid_version"
    UNKNOWN_KEY = "sesame_unknown_key"
    EXPIRED_TIMESTAMP = "sesame_expired_timestamp"
    REPLAY_DETECTED = "sesame_replay_detected"
    SIGNATURE_MISMATCH = "sesame_signature_mismatch"
    SCOPE_DENIED = "sesame_scope_denied"
    DECRYPT_FAILED = "sesame_decrypt_failed"
    KEY_REVOKED = "sesame_key_revoked"


_HTTP_STATUS = {
    SesameErrorCode.INVALID_VERSION: 400,
    SesameErrorCode.DECRYPT_FAILED: 400,
    SesameErrorCode.SCOPE_DENIED: 403,
}


class SesameError(Exception):
    """A SESAME verification/signing failure, fail-closed (Appendix A.7)."""

    def __init__(self, code: SesameErrorCode):
        self.code = code
        super().__init__(code.value)

    @property
    def http_status(self) -> int:
        return _HTTP_STATUS.get(self.code, 401)


@dataclass
class SesameHeaders:
    version: Optional[str] = None
    key_id: Optional[str] = None
    timestamp: Optional[str] = None
    nonce: Optional[str] = None
    signature: Optional[str] = None
    scope: Optional[str] = None
    encrypted: bool = False
    enc_key_id: Optional[str] = None
    iv: Optional[str] = None

    def is_absent(self) -> bool:
        """True when no Tier-1 headers are present (Tier 0)."""
        return not any(
            [self.version, self.key_id, self.timestamp, self.nonce, self.signature]
        )

    @classmethod
    def from_lookup(cls, get: Callable[[str], Optional[str]]) -> "SesameHeaders":
        """Parse from a case-insensitive `name -> value` lookup callable."""
        enc = get(Header.ENCRYPTED)
        return cls(
            version=get(Header.VERSION),
            key_id=get(Header.KEY_ID),
            timestamp=get(Header.TIMESTAMP),
            nonce=get(Header.NONCE),
            signature=get(Header.SIGNATURE),
            scope=get(Header.SCOPE),
            encrypted=(enc is not None and enc.lower() == "true"),
            enc_key_id=get(Header.ENC_KEY_ID),
            iv=get(Header.IV),
        )
