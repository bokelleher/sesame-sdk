"""SESAME: the proposed SCTE 130-9 security layer for the ESAM interface.

A native Python implementation of draft v0.5, proven byte-for-byte against the
same golden vectors as the Rust crate, the C++ SDK, and the deployed rust-pois
reference. PyPI package: ``sesame-esam``; import name: ``sesame``.
"""

from __future__ import annotations

from . import canonical, keys, message, protocol, replay, tier1, tier3
from .keys import ChannelScope, KeyProvider, StaticKeyProvider
from .message import (
    Header,
    PROTOCOL_VERSION,
    SesameError,
    SesameErrorCode,
    SesameHeaders,
)
from .protocol import (
    RequestContext,
    ResponseParams,
    SesameConfig,
    SignedResponse,
    Tier,
    VerifiedRequest,
    format_rfc3339_utc,
    parse_scope_channel,
    sign_response,
    verify_request,
)
from .replay import InMemoryReplayCache, ReplayCache

__version__ = "0.1.0"

__all__ = [
    "canonical",
    "tier1",
    "tier3",
    "message",
    "keys",
    "replay",
    "protocol",
    "Header",
    "PROTOCOL_VERSION",
    "SesameError",
    "SesameErrorCode",
    "SesameHeaders",
    "ChannelScope",
    "KeyProvider",
    "StaticKeyProvider",
    "ReplayCache",
    "InMemoryReplayCache",
    "Tier",
    "SesameConfig",
    "VerifiedRequest",
    "RequestContext",
    "SignedResponse",
    "ResponseParams",
    "verify_request",
    "sign_response",
    "format_rfc3339_utc",
    "parse_scope_channel",
]
