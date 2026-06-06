"""Tier 3: AES-256-GCM payload encryption (96-bit IV, 128-bit tag)."""

from __future__ import annotations

from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
IV_LEN = 12
TAG_LEN = 16


def aad_for_headers(
    version: str,
    key_id: str,
    timestamp: str,
    nonce: str,
    scope: Optional[str] = None,
) -> bytes:
    """version LF key-id LF timestamp LF nonce [LF scope]."""
    fields = [version, key_id, timestamp, nonce]
    if scope is not None:
        fields.append(scope)
    return "\n".join(fields).encode("utf-8")


def seal(key: bytes, iv: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Encrypt, returning ciphertext || 16-byte tag."""
    return AESGCM(key).encrypt(iv, plaintext, aad)


def open(key: bytes, iv: bytes, aad: bytes, ct_and_tag: bytes) -> Optional[bytes]:
    """Decrypt ciphertext || tag; None on authentication failure."""
    try:
        return AESGCM(key).decrypt(iv, ct_and_tag, aad)
    except InvalidTag:
        return None
