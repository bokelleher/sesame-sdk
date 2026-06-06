"""Known-answer tests (RFC 4231, NIST SP 800-38D), a full sign/verify
round-trip, and the negative matrix, mirroring the Rust/C++ SDK tests."""

import pytest

from sesame import (
    ChannelScope,
    Header,
    InMemoryReplayCache,
    PROTOCOL_VERSION,
    RequestContext,
    ResponseParams,
    SesameConfig,
    SesameError,
    SesameErrorCode,
    SesameHeaders,
    StaticKeyProvider,
    Tier,
    canonical,
    sign_response,
    tier1,
    tier3,
    verify_request,
)

XML = b'<?xml version="1.0"?><SignalProcessingEvent/>'


def test_sha256_empty():
    assert (
        canonical.body_hash_hex(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_rfc4231_hmac():
    assert (
        tier1.sign(b"Jefe", "what do ya want for nothing?")
        == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


def test_nist_gcm():
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    pt = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    expected = bytes.fromhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        "76fc6ece0f4e1768cddf8853bb2d551b"
    )
    assert tier3.seal(key, iv, aad, pt) == expected


def test_freshness():
    now = tier1.parse_rfc3339_utc("2026-02-24T18:05:00Z")
    assert tier1.check_freshness("2026-02-24T18:00:00Z", now, 300)
    assert not tier1.check_freshness("2026-02-24T17:59:59Z", now, 300)
    assert not tier1.check_freshness("not-a-date", now, 300)


def _provider():
    p = StaticKeyProvider()
    p.with_signing_key("sas-east-01", b"client-secret", ChannelScope.list(["SportsFeed-East"]))
    p.with_signing_key("pois-primary", b"pois-secret", ChannelScope.all())
    p.with_aead_key("enc-sportsfeed-2026q1", bytes([0x42]) * 32)
    return p


def _now():
    return tier1.parse_rfc3339_utc("2026-02-24T18:00:00Z")


def _ctx():
    return RequestContext("POST", "/esam?channel=SportsFeed-East", "SportsFeed-East")


def _make(tier, p):
    ts = "2026-02-24T18:00:00Z"
    nonce = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    scope = "channel=SportsFeed-East" if tier >= Tier.TWO else None
    h = SesameHeaders(
        version=PROTOCOL_VERSION, key_id="sas-east-01", timestamp=ts, nonce=nonce, scope=scope
    )
    if tier >= Tier.THREE:
        aead = p.aead_key("enc-sportsfeed-2026q1")
        iv = bytes(12)
        aad = tier3.aad_for_headers(PROTOCOL_VERSION, "sas-east-01", ts, nonce, scope)
        body = tier3.seal(aead, iv, aad, XML)
        h.encrypted = True
        h.enc_key_id = "enc-sportsfeed-2026q1"
        h.iv = iv.hex()
    else:
        body = XML
    bh = canonical.body_hash_hex(body)
    canon = canonical.request_canonical(
        "POST", "/esam?channel=SportsFeed-East", ts, nonce, bh, scope
    )
    h.signature = tier1.sign(p.primary_signing_key("sas-east-01"), canon)
    return h, body


def _verify(p, h, body, now, tier, cache=None):
    if cache is None:
        cache = InMemoryReplayCache(300)
    return verify_request(SesameConfig(), p, cache, _ctx(), h, body, now, tier)


@pytest.mark.parametrize("tier", [Tier.ONE, Tier.TWO, Tier.THREE])
def test_roundtrip(tier):
    p = _provider()
    h, body = _make(tier, p)
    v = _verify(p, h, body, _now(), tier)
    assert v.plaintext == XML
    assert v.achieved_tier == tier


def _expect(code, fn):
    with pytest.raises(SesameError) as ei:
        fn()
    assert ei.value.code == code


def test_tampered_body():
    p = _provider()
    h, body = _make(Tier.ONE, p)
    _expect(SesameErrorCode.SIGNATURE_MISMATCH, lambda: _verify(p, h, body + b"X", _now(), Tier.ONE))


def test_replay():
    p = _provider()
    h, body = _make(Tier.ONE, p)
    cache = InMemoryReplayCache(300)
    _verify(p, h, body, _now(), Tier.ONE, cache)
    _expect(SesameErrorCode.REPLAY_DETECTED, lambda: _verify(p, h, body, _now(), Tier.ONE, cache))


def test_stale():
    p = _provider()
    h, body = _make(Tier.ONE, p)
    _expect(SesameErrorCode.EXPIRED_TIMESTAMP, lambda: _verify(p, h, body, _now() + 600, Tier.ONE))


def test_unknown_key():
    p = _provider()
    h, body = _make(Tier.ONE, p)
    h.key_id = "ghost"
    _expect(SesameErrorCode.UNKNOWN_KEY, lambda: _verify(p, h, body, _now(), Tier.ONE))


def test_wrong_version():
    p = _provider()
    h, body = _make(Tier.ONE, p)
    h.version = "2.0"
    _expect(SesameErrorCode.INVALID_VERSION, lambda: _verify(p, h, body, _now(), Tier.ONE))


def test_truncated_tag():
    p = _provider()
    h, body = _make(Tier.THREE, p)
    _expect(SesameErrorCode.SIGNATURE_MISMATCH, lambda: _verify(p, h, body[:-1], _now(), Tier.THREE))


def test_sign_response_and_forged_detection():
    p = _provider()
    params = ResponseParams(
        signing_key_id="pois-primary",
        correlation="ap-1:sig-001",
        scope="channel=SportsFeed-East",
        tier=Tier.TWO,
    )
    r = sign_response(SesameConfig(), p, params, XML, _now())
    hd = dict(r.headers)
    bh = canonical.body_hash_hex(r.body)
    canon = canonical.response_canonical(
        "ap-1:sig-001", hd[Header.TIMESTAMP], hd[Header.NONCE], bh, "channel=SportsFeed-East"
    )
    key = p.primary_signing_key("pois-primary")
    assert tier1.verify(key, canon, hd[Header.SIGNATURE])
    forged = canonical.response_canonical(
        "ap-1:sig-001",
        hd[Header.TIMESTAMP],
        hd[Header.NONCE],
        canonical.body_hash_hex(b"<blackout/>"),
        "channel=SportsFeed-East",
    )
    assert not tier1.verify(key, forged, hd[Header.SIGNATURE])
