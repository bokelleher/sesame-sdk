#!/usr/bin/env python3
"""A minimal SESAME client. Builds a signed (and optionally AES-256-GCM-
encrypted) ESAM request with this SDK's primitives, then self-verifies it with
verify_request (the same oracle a server runs) before it would go on the wire.

Run: python examples/sign_request.py [1|2|3]   # tier, default 1
"""

import os
import sys
import time

from sesame import (
    ChannelScope,
    Header,
    InMemoryReplayCache,
    PROTOCOL_VERSION,
    RequestContext,
    SesameConfig,
    SesameHeaders,
    StaticKeyProvider,
    Tier,
    canonical,
    format_rfc3339_utc,
    tier1,
    tier3,
    verify_request,
)


def main() -> int:
    tier_n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    tier = Tier.THREE if tier_n >= 3 else (Tier.TWO if tier_n == 2 else Tier.ONE)

    provider = StaticKeyProvider()
    provider.with_signing_key("sas-east-01", b"shared-secret", ChannelScope.list(["SportsFeed-East"]))
    provider.with_aead_key("enc-2026q1", bytes(range(1, 33)))

    xml = b'<?xml version="1.0"?><SignalProcessingNotification/>'
    path = "/esam?channel=SportsFeed-East"
    key_id = "sas-east-01"

    now = int(time.time())
    timestamp = format_rfc3339_utc(now)
    nonce = os.urandom(16).hex()
    scope = "channel=SportsFeed-East" if tier >= Tier.TWO else None

    h = SesameHeaders(
        version=PROTOCOL_VERSION, key_id=key_id, timestamp=timestamp, nonce=nonce, scope=scope
    )
    if tier >= Tier.THREE:
        aead = provider.aead_key("enc-2026q1")
        iv = os.urandom(12)
        aad = tier3.aad_for_headers(PROTOCOL_VERSION, key_id, timestamp, nonce, scope)
        body = tier3.seal(aead, iv, aad, xml)
        h.encrypted = True
        h.enc_key_id = "enc-2026q1"
        h.iv = iv.hex()
    else:
        body = xml

    body_hash = canonical.body_hash_hex(body)
    canon = canonical.request_canonical("POST", path, timestamp, nonce, body_hash, scope)
    h.signature = tier1.sign(provider.primary_signing_key(key_id), canon)

    ctx = RequestContext("POST", path, "SportsFeed-East")
    verified = verify_request(SesameConfig(), provider, InMemoryReplayCache(300), ctx, h, body, now, tier)

    print(f"POST {path}  (Tier {int(tier)})")

    def show(name, val):
        if val:
            print(f"  {name}: {val}")

    show(Header.VERSION, h.version)
    show(Header.KEY_ID, h.key_id)
    show(Header.TIMESTAMP, h.timestamp)
    show(Header.NONCE, h.nonce)
    show(Header.SCOPE, h.scope)
    if h.encrypted:
        show(Header.ENCRYPTED, "true")
        show(Header.ENC_KEY_ID, h.enc_key_id)
        show(Header.IV, h.iv)
    show(Header.SIGNATURE, h.signature)
    kind = "ciphertext||tag" if h.encrypted else "cleartext XML"
    print(f"  body: {len(body)} bytes ({kind})")
    print(f"self-verify OK: achieved Tier {int(verified.achieved_tier)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
