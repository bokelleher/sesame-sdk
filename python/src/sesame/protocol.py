"""The high-level SESAME API: verify_request / sign_response.

Mirrors the Rust crate and C++ SDK. Failures raise ``SesameError`` (the
Pythonic equivalent of the Result types in the other SDKs).
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from . import canonical, tier1, tier3
from .keys import KeyProvider
from .message import Header, PROTOCOL_VERSION, SesameError, SesameErrorCode, SesameHeaders
from .replay import ReplayCache


class Tier(enum.IntEnum):
    ZERO = 0
    ONE = 1
    TWO = 2
    THREE = 3


@dataclass
class SesameConfig:
    replay_window_secs: int = 300


@dataclass
class VerifiedRequest:
    plaintext: bytes
    key_id: str
    scope_channel: Optional[str]
    achieved_tier: Tier


@dataclass
class RequestContext:
    method: str
    path: str
    target_channel: Optional[str] = None


@dataclass
class SignedResponse:
    headers: List[Tuple[str, str]]
    body: bytes
    content_type: str


@dataclass
class ResponseParams:
    signing_key_id: str
    correlation: str
    scope: Optional[str] = None
    tier: Tier = Tier.ONE
    enc_key_id: Optional[str] = None


def format_rfc3339_utc(unix_secs: int) -> str:
    return datetime.fromtimestamp(unix_secs, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_scope_channel(scope: str) -> Optional[str]:
    prefix = "channel="
    if not scope.startswith(prefix):
        return None
    return scope[len(prefix):].strip()


def verify_request(
    cfg: SesameConfig,
    provider: KeyProvider,
    replay: ReplayCache,
    ctx: RequestContext,
    headers: SesameHeaders,
    raw_body: bytes,
    now_unix: int,
    min_tier: Tier,
) -> VerifiedRequest:
    """Verify an inbound ESAM request. Raises SesameError on any failure."""
    # Tier 0: unauthenticated passthrough, only when policy permits it.
    if headers.is_absent():
        if min_tier == Tier.ZERO:
            return VerifiedRequest(raw_body, "", None, Tier.ZERO)
        raise SesameError(SesameErrorCode.MISSING_HEADERS)

    if not all(
        [headers.version, headers.key_id, headers.timestamp, headers.nonce, headers.signature]
    ):
        raise SesameError(SesameErrorCode.MISSING_HEADERS)
    version = headers.version
    key_id = headers.key_id
    timestamp = headers.timestamp
    nonce = headers.nonce
    signature = headers.signature

    if version != PROTOCOL_VERSION:
        raise SesameError(SesameErrorCode.INVALID_VERSION)
    if not tier1.check_freshness(timestamp, now_unix, cfg.replay_window_secs):
        raise SesameError(SesameErrorCode.EXPIRED_TIMESTAMP)
    if provider.is_revoked(key_id):
        raise SesameError(SesameErrorCode.KEY_REVOKED)
    signing_keys = provider.signing_keys(key_id)
    if not signing_keys:
        raise SesameError(SesameErrorCode.UNKNOWN_KEY)

    scope = headers.scope
    body_hash = canonical.body_hash_hex(raw_body)
    canon = canonical.request_canonical(ctx.method, ctx.path, timestamp, nonce, body_hash, scope)
    if not tier1.verify_any(signing_keys, canon, signature):
        raise SesameError(SesameErrorCode.SIGNATURE_MISMATCH)

    if not replay.check_and_remember(key_id, nonce, now_unix):
        raise SesameError(SesameErrorCode.REPLAY_DETECTED)

    achieved = Tier.ONE
    scope_channel: Optional[str] = None

    if scope is not None:
        declared = parse_scope_channel(scope)
        if declared is None:
            raise SesameError(SesameErrorCode.SCOPE_DENIED)
        if ctx.target_channel is not None and ctx.target_channel != declared:
            raise SesameError(SesameErrorCode.SCOPE_DENIED)
        if not provider.is_authorized(key_id, declared):
            raise SesameError(SesameErrorCode.SCOPE_DENIED)
        scope_channel = declared
        achieved = Tier.TWO
    elif min_tier >= Tier.TWO:
        raise SesameError(SesameErrorCode.SCOPE_DENIED)

    if headers.encrypted:
        if not headers.enc_key_id or not headers.iv:
            raise SesameError(SesameErrorCode.DECRYPT_FAILED)
        try:
            iv = bytes.fromhex(headers.iv)
        except ValueError:
            raise SesameError(SesameErrorCode.DECRYPT_FAILED)
        if len(iv) != tier3.IV_LEN:
            raise SesameError(SesameErrorCode.DECRYPT_FAILED)
        aead = provider.aead_key(headers.enc_key_id)
        if aead is None:
            raise SesameError(SesameErrorCode.DECRYPT_FAILED)
        aad = tier3.aad_for_headers(version, key_id, timestamp, nonce, scope)
        pt = tier3.open(aead, iv, aad, raw_body)
        if pt is None:
            raise SesameError(SesameErrorCode.DECRYPT_FAILED)
        plaintext = pt
        achieved = Tier.THREE
    elif min_tier >= Tier.THREE:
        raise SesameError(SesameErrorCode.DECRYPT_FAILED)
    else:
        plaintext = raw_body

    if achieved < min_tier:
        raise SesameError(SesameErrorCode.MISSING_HEADERS)

    return VerifiedRequest(plaintext, key_id, scope_channel, achieved)


def sign_response(
    cfg: SesameConfig,
    provider: KeyProvider,
    params: ResponseParams,
    plaintext_xml: bytes,
    now_unix: int,
) -> SignedResponse:
    """Sign (and optionally encrypt) an outbound ESAM response."""
    del cfg  # reserved (window not needed when signing)
    signing_key = provider.primary_signing_key(params.signing_key_id)
    if signing_key is None:
        raise SesameError(SesameErrorCode.UNKNOWN_KEY)

    timestamp = format_rfc3339_utc(now_unix)
    nonce = os.urandom(16).hex()

    headers: List[Tuple[str, str]] = [
        (Header.VERSION, PROTOCOL_VERSION),
        (Header.KEY_ID, params.signing_key_id),
        (Header.TIMESTAMP, timestamp),
        (Header.NONCE, nonce),
    ]
    if params.scope is not None:
        headers.append((Header.SCOPE, params.scope))

    if params.tier >= Tier.THREE:
        if params.enc_key_id is None:
            raise SesameError(SesameErrorCode.DECRYPT_FAILED)
        aead = provider.aead_key(params.enc_key_id)
        if aead is None:
            raise SesameError(SesameErrorCode.DECRYPT_FAILED)
        iv = os.urandom(tier3.IV_LEN)
        aad = tier3.aad_for_headers(
            PROTOCOL_VERSION, params.signing_key_id, timestamp, nonce, params.scope
        )
        body = tier3.seal(aead, iv, aad, plaintext_xml)
        headers += [
            (Header.ENCRYPTED, "true"),
            (Header.ENC_KEY_ID, params.enc_key_id),
            (Header.IV, iv.hex()),
        ]
        content_type = "application/octet-stream"
    else:
        body = plaintext_xml
        content_type = "application/xml"

    body_hash = canonical.body_hash_hex(body)
    canon = canonical.response_canonical(params.correlation, timestamp, nonce, body_hash, params.scope)
    headers.append((Header.SIGNATURE, tier1.sign(signing_key, canon)))

    return SignedResponse(headers, body, content_type)
