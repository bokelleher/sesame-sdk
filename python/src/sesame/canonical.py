"""SESAME canonical strings (draft v0.5).

Byte-identical to the Rust crate and C++ SDK: the same fields, the same LF
separators, no trailing newline.
"""

from __future__ import annotations

import hashlib
from typing import Optional


def body_hash_hex(body: bytes) -> str:
    """Lowercase-hex SHA-256 of the (possibly-encrypted) body."""
    return hashlib.sha256(body).hexdigest()


def request_canonical(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_hash_hex: str,
    scope: Optional[str] = None,
) -> str:
    """method LF path LF timestamp LF nonce LF body-hash [LF scope]."""
    fields = [method, path, timestamp, nonce, body_hash_hex]
    if scope is not None:
        fields.append(scope)
    return "\n".join(fields)


def response_canonical(
    correlation: str,
    timestamp: str,
    nonce: str,
    body_hash_hex: str,
    scope: Optional[str] = None,
) -> str:
    """"RESPONSE" LF correlation LF timestamp LF nonce LF body-hash [LF scope]."""
    fields = ["RESPONSE", correlation, timestamp, nonce, body_hash_hex]
    if scope is not None:
        fields.append(scope)
    return "\n".join(fields)
