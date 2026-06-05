//! # SESAME
//!
//! Secure ESAM Authentication and Message Encryption: the proposed SCTE 130-9
//! security layer for the ESAM interface. A portable, framework-agnostic core
//! implementing the three additive tiers of **ANSI/SCTE 130-9 (SESAME) draft
//! v0.5**, bidirectionally (verify inbound requests, sign/encrypt outbound
//! responses), all carried in HTTP headers with no ESAM XML schema change.
//!
//! | Tier | Capability | Mechanism |
//! |---|---|---|
//! | 0 | Unauthenticated baseline | no SESAME headers (backward compatible) |
//! | 1 | Authentication + integrity | HMAC-SHA256 over a canonical string |
//! | 2 | Channel-scoped authorization | signed `X-SESAME-Scope`, policy lookup |
//! | 3 | Payload encryption | AES-256-GCM (96-bit IV, 128-bit tag) |
//!
//! ## Provenance
//!
//! This crate is the canonical home of the SESAME protocol, extracted
//! byte-for-byte from the `rust-pois` reference implementation (originally MIT,
//! © POIS Contributors). The deployed `rust-pois` server is intended to depend
//! on this crate so the protocol lives in exactly one place. Byte-level
//! conformance is pinned by the golden vectors in `test-vectors/`, which are
//! generated from `rust-pois` and reproduced by `tests/conformance.rs`.
//!
//! ## Design
//!
//! - **No I/O, no HTTP framework.** [`verify_request`] / [`sign_response`] take
//!   the request parts, the parsed [`SesameHeaders`], the body, and `now`.
//! - **Host owns the resources** via injected traits: the key directory
//!   ([`KeyProvider`](keys::KeyProvider)) and the replay memory
//!   ([`ReplayCache`](replay::ReplayCache)). The reference in-memory replay
//!   cache ships; distributed stores are the host's concern.
//! - **RNG is feature-gated.** Verification is RNG-free. Signing responses needs
//!   a fresh nonce/IV, so [`sign_response`] and the IV/nonce helpers sit behind
//!   the default-on `rng` feature; disable it for verify-only/embedded hosts.
//!
//! ## Wire format
//!
//! See [`SESAME.md`](https://github.com/bokelleher/sesame-sdk/blob/main/SESAME.md)
//! for the byte-exact specification (canonical strings, headers, encodings).

#![forbid(unsafe_code)]

pub mod canonical;
pub mod keys;
pub mod message;
pub mod replay;
pub mod tier1_hmac;
pub mod tier2_authz;
pub mod tier3_aead;

#[cfg(feature = "axum")]
pub mod axum_adapter;

#[cfg(feature = "serde")]
pub mod vectors;

use time::OffsetDateTime;

pub use crate::message::{SesameError, SesameHeaders};

use crate::keys::KeyProvider;
use crate::message::{hex_decode, PROTOCOL_VERSION};
use crate::replay::ReplayCache;

/// A SESAME security tier. Tiers are additive (Tier N implies Tier 1..N).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Unauthenticated baseline (Appendix A.1), backward-compatible passthrough.
    Zero = 0,
    /// Authentication + integrity (HMAC-SHA256).
    One = 1,
    /// + channel-scoped authorization.
    Two = 2,
    /// + AES-256-GCM payload encryption.
    Three = 3,
}

impl Tier {
    pub fn from_u8(n: u8) -> Tier {
        match n {
            0 => Tier::Zero,
            1 => Tier::One,
            2 => Tier::Two,
            _ => Tier::Three,
        }
    }

    /// Numeric tier level (0..3).
    pub fn level(self) -> u8 {
        self as u8
    }
}

/// Deployment-wide SESAME configuration.
#[derive(Debug, Clone)]
pub struct SesameConfig {
    /// Replay/freshness window in seconds (§8.5 item 6; default 300).
    pub replay_window_secs: i64,
}

impl Default for SesameConfig {
    fn default() -> Self {
        SesameConfig {
            replay_window_secs: 300,
        }
    }
}

/// Outcome of verifying an inbound request.
pub struct VerifiedRequest {
    /// The decrypted ESAM XML body (== raw body when Tier 3 was not used).
    pub plaintext: Vec<u8>,
    /// Authenticated signing key-id.
    pub key_id: String,
    /// Declared channel scope, if Tier 2 was used.
    pub scope_channel: Option<String>,
    /// Highest tier satisfied by this request.
    pub achieved_tier: Tier,
}

/// A signed (and optionally encrypted) outbound response ready to send.
pub struct SignedResponse {
    /// SESAME headers to attach (name, value).
    pub headers: Vec<(&'static str, String)>,
    /// The response body bytes (ciphertext when Tier 3, else the XML).
    pub body: Vec<u8>,
    /// Content-Type to set (`application/octet-stream` when encrypted, §8.4).
    pub content_type: &'static str,
}

/// Context needed to verify a request.
pub struct RequestContext<'a> {
    pub method: &'a str,
    /// Exact request-target (path + query) as signed, e.g.
    /// `/esam?channel=SportsFeed-East` (§8.2.3).
    pub path: &'a str,
    /// The channel the request actually targets (route/query/body-resolved),
    /// used to cross-check the Tier-2 scope. May be `None` pre-resolution.
    pub target_channel: Option<&'a str>,
}

/// Verify an inbound ESAM request against the SESAME protocol.
///
/// `min_tier` is the channel's minimum required tier (§9.3). When `min_tier` is
/// `Tier::Zero` and no SESAME headers are present, the request passes through
/// unauthenticated (backward compatibility). Fails closed at each step with the
/// distinct `SesameError` from Appendix A.7.
#[allow(clippy::too_many_arguments)]
pub fn verify_request(
    cfg: &SesameConfig,
    provider: &dyn KeyProvider,
    replay: &dyn ReplayCache,
    ctx: &RequestContext<'_>,
    headers: &SesameHeaders,
    raw_body: &[u8],
    now: OffsetDateTime,
    min_tier: Tier,
) -> Result<VerifiedRequest, SesameError> {
    // Tier 0: unauthenticated passthrough, only when the policy permits it.
    if headers.is_absent() {
        if min_tier == Tier::Zero {
            return Ok(VerifiedRequest {
                plaintext: raw_body.to_vec(),
                key_id: String::new(),
                scope_channel: None,
                achieved_tier: Tier::Zero,
            });
        }
        return Err(SesameError::MissingHeaders);
    }

    // --- Tier 1: authentication + integrity ---
    let t1 = headers.require_tier1()?;

    if t1.version != PROTOCOL_VERSION {
        return Err(SesameError::InvalidVersion);
    }

    // Freshness (cheap, do before key lookup to shed obviously-stale traffic).
    tier1_hmac::check_freshness(t1.timestamp, now, cfg.replay_window_secs)?;

    // Key lookup + revocation.
    if provider.is_revoked(t1.key_id) {
        return Err(SesameError::KeyRevoked);
    }
    let signing_keys: Vec<Vec<u8>> = provider
        .signing_keys(t1.key_id)
        .into_iter()
        .map(|k| k.0)
        .collect();
    if signing_keys.is_empty() {
        return Err(SesameError::UnknownKey);
    }

    // Canonical string is computed over the body AS TRANSMITTED (ciphertext when
    // encrypted -> encrypt-then-MAC).
    let body_hash = canonical::body_hash_hex(raw_body);
    let scope_for_sig = headers.scope.as_deref();
    let canonical = canonical::request_canonical(
        ctx.method,
        ctx.path,
        t1.timestamp,
        t1.nonce,
        &body_hash,
        scope_for_sig,
    );
    tier1_hmac::verify_any(&signing_keys, &canonical, t1.signature)?;

    // Replay only AFTER the signature is valid, so an attacker cannot poison the
    // cache with unauthenticated nonces.
    if !replay.check_and_remember(t1.key_id, t1.nonce, now.unix_timestamp()) {
        return Err(SesameError::ReplayDetected);
    }

    let mut achieved = Tier::One;
    let mut scope_channel = None;

    // --- Tier 2: authorization ---
    if let Some(scope) = headers.scope.as_deref() {
        let channel = tier2_authz::authorize(provider, t1.key_id, scope, ctx.target_channel)?;
        scope_channel = Some(channel);
        achieved = Tier::Two;
    } else if min_tier >= Tier::Two {
        // Policy requires Tier 2 but no scope was declared.
        return Err(SesameError::ScopeDenied);
    }

    // --- Tier 3: decryption ---
    let plaintext = if headers.encrypted {
        let enc_key_id = headers
            .enc_key_id
            .as_deref()
            .ok_or(SesameError::DecryptFailed)?;
        let iv_hex = headers.iv.as_deref().ok_or(SesameError::DecryptFailed)?;
        let iv_bytes = hex_decode(iv_hex).ok_or(SesameError::DecryptFailed)?;
        if iv_bytes.len() != tier3_aead::IV_LEN {
            return Err(SesameError::DecryptFailed);
        }
        let mut iv = [0u8; tier3_aead::IV_LEN];
        iv.copy_from_slice(&iv_bytes);
        let aead = provider
            .aead_key(enc_key_id)
            .ok_or(SesameError::DecryptFailed)?;
        let aad = tier3_aead::aad_for_headers(
            t1.version,
            t1.key_id,
            t1.timestamp,
            t1.nonce,
            scope_for_sig,
        );
        let pt = tier3_aead::open(&aead.0, &iv, &aad, raw_body)?;
        achieved = Tier::Three;
        pt
    } else if min_tier >= Tier::Three {
        return Err(SesameError::DecryptFailed);
    } else {
        raw_body.to_vec()
    };

    if achieved < min_tier {
        // Authenticated but below the channel's required tier.
        return Err(SesameError::MissingHeaders);
    }

    Ok(VerifiedRequest {
        plaintext,
        key_id: t1.key_id.to_string(),
        scope_channel,
        achieved_tier: achieved,
    })
}

/// Parameters for signing an outbound response.
pub struct ResponseParams<'a> {
    /// This node's signing key-id (e.g. `pois-primary`), placed in X-SESAME-KeyId.
    pub signing_key_id: &'a str,
    /// acquisitionSignalID being answered, binds the response to its request
    /// ([BO] response correlation, see canonical.rs).
    pub correlation: &'a str,
    /// Channel scope to echo (Tier 2+), as `channel=<id>`. `None` below Tier 2.
    pub scope: Option<&'a str>,
    /// Tier to emit. Must be <= the tiers this node can satisfy with its keys.
    pub tier: Tier,
    /// Encryption key-id for Tier 3 (X-SESAME-EncKeyId).
    pub enc_key_id: Option<&'a str>,
}

/// Sign (and optionally encrypt) an outbound ESAM response. This is the primary
/// SESAME protection: it authenticates the POIS's conditioning decision so a
/// forged/tampered response (spoofed blackout/avail/redirect) is detectable.
///
/// A fresh nonce and (for Tier 3) a fresh IV are drawn from the OS CSPRNG per
/// call, never reused (contrast Appendix A.4, [BO] item 4).
#[cfg(feature = "rng")]
pub fn sign_response(
    cfg: &SesameConfig,
    provider: &dyn KeyProvider,
    params: &ResponseParams<'_>,
    plaintext_xml: &[u8],
    now: OffsetDateTime,
) -> Result<SignedResponse, SesameError> {
    use crate::message::hex_encode;
    use time::format_description::well_known::Rfc3339;

    let _ = cfg; // reserved (window not needed when signing)
    let signing_key = provider
        .primary_signing_key(params.signing_key_id)
        .ok_or(SesameError::UnknownKey)?;

    let timestamp = now
        .format(&Rfc3339)
        .map_err(|_| SesameError::ExpiredTimestamp)?;
    let nonce = hex_encode(&random_128());

    let mut headers: Vec<(&'static str, String)> = vec![
        (message::H_VERSION, PROTOCOL_VERSION.to_string()),
        (message::H_KEY_ID, params.signing_key_id.to_string()),
        (message::H_TIMESTAMP, timestamp.clone()),
        (message::H_NONCE, nonce.clone()),
    ];
    if let Some(scope) = params.scope {
        headers.push((message::H_SCOPE, scope.to_string()));
    }

    // Tier 3: encrypt the body first (encrypt-then-MAC).
    let (body, content_type): (Vec<u8>, &'static str) = if params.tier >= Tier::Three {
        let enc_key_id = params.enc_key_id.ok_or(SesameError::DecryptFailed)?;
        let aead = provider
            .aead_key(enc_key_id)
            .ok_or(SesameError::DecryptFailed)?;
        let iv = tier3_aead::random_iv();
        let aad = tier3_aead::aad_for_headers(
            PROTOCOL_VERSION,
            params.signing_key_id,
            &timestamp,
            &nonce,
            params.scope,
        );
        let ct = tier3_aead::seal(&aead.0, &iv, &aad, plaintext_xml)?;
        headers.push((message::H_ENCRYPTED, "true".to_string()));
        headers.push((message::H_ENC_KEY_ID, enc_key_id.to_string()));
        headers.push((message::H_IV, hex_encode(&iv)));
        (ct, "application/octet-stream")
    } else {
        (plaintext_xml.to_vec(), "application/xml")
    };

    // Tier 1: sign over the (possibly-encrypted) body.
    let body_hash = canonical::body_hash_hex(&body);
    let canonical = canonical::response_canonical(
        params.correlation,
        &timestamp,
        &nonce,
        &body_hash,
        params.scope,
    );
    let signature = tier1_hmac::sign(&signing_key.0, &canonical);
    headers.push((message::H_SIGNATURE, signature));

    Ok(SignedResponse {
        headers,
        body,
        content_type,
    })
}

/// 128 bits from the OS CSPRNG (nonces, §8.5 item 5 / RFC 4086).
#[cfg(feature = "rng")]
fn random_128() -> [u8; 16] {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b
}

// ---------------------------------------------------------------------------
// Integration-level tests: full positive round-trips and the negative matrix.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AeadKey, ChannelScope, HmacKey, StaticKeyProvider};
    use crate::message::hex_encode;
    use crate::replay::InMemoryReplayCache;
    use crate::tier3_aead::KEY_LEN;
    use time::format_description::well_known::Rfc3339;

    const XML: &[u8] = b"<?xml version=\"1.0\"?><SignalProcessingEvent/>";

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-02-24T18:00:00Z", &Rfc3339).unwrap()
    }

    fn provider() -> StaticKeyProvider {
        StaticKeyProvider::new()
            .with_signing_key(
                "sas-east-01",
                HmacKey(b"client-secret".to_vec()),
                ChannelScope::list(["SportsFeed-East"]),
            )
            .with_signing_key(
                "pois-primary",
                HmacKey(b"pois-secret".to_vec()),
                ChannelScope::all(),
            )
            .with_aead_key("enc-sportsfeed-2026q1", AeadKey([0x42; KEY_LEN]))
    }

    /// Build a signed Tier-1/2/3 request the way a conformant client would, then
    /// return (headers, body) for verify_request.
    fn make_request(tier: Tier, encrypt_with: Option<&str>) -> (SesameHeaders, Vec<u8>) {
        let p = provider();
        let key = p.primary_signing_key("sas-east-01").unwrap().0;
        let timestamp = "2026-02-24T18:00:00Z";
        let nonce = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        let scope = if tier >= Tier::Two {
            Some("channel=SportsFeed-East")
        } else {
            None
        };

        let (body, enc_headers) = if tier >= Tier::Three {
            let enc_key_id = encrypt_with.unwrap_or("enc-sportsfeed-2026q1");
            let aead = p.aead_key(enc_key_id).unwrap();
            let iv = [0u8; tier3_aead::IV_LEN];
            let aad = tier3_aead::aad_for_headers(
                PROTOCOL_VERSION,
                "sas-east-01",
                timestamp,
                nonce,
                scope,
            );
            let ct = tier3_aead::seal(&aead.0, &iv, &aad, XML).unwrap();
            (ct, Some((enc_key_id.to_string(), hex_encode(&iv))))
        } else {
            (XML.to_vec(), None)
        };

        let body_hash = canonical::body_hash_hex(&body);
        let canonical = canonical::request_canonical(
            "POST",
            "/esam?channel=SportsFeed-East",
            timestamp,
            nonce,
            &body_hash,
            scope,
        );
        let signature = tier1_hmac::sign(&key, &canonical);

        let headers = SesameHeaders {
            version: Some(PROTOCOL_VERSION.to_string()),
            key_id: Some("sas-east-01".to_string()),
            timestamp: Some(timestamp.to_string()),
            nonce: Some(nonce.to_string()),
            signature: Some(signature),
            scope: scope.map(|s| s.to_string()),
            encrypted: enc_headers.is_some(),
            enc_key_id: enc_headers.as_ref().map(|(k, _)| k.clone()),
            iv: enc_headers.as_ref().map(|(_, iv)| iv.clone()),
        };
        (headers, body)
    }

    fn ctx() -> RequestContext<'static> {
        RequestContext {
            method: "POST",
            path: "/esam?channel=SportsFeed-East",
            target_channel: Some("SportsFeed-East"),
        }
    }

    #[test]
    fn tier1_roundtrip() {
        let (h, body) = make_request(Tier::One, None);
        let cache = InMemoryReplayCache::new(300);
        let v = verify_request(
            &SesameConfig::default(),
            &provider(),
            &cache,
            &ctx(),
            &h,
            &body,
            now(),
            Tier::One,
        )
        .expect("tier1 must verify");
        assert_eq!(v.plaintext, XML);
        assert_eq!(v.achieved_tier, Tier::One);
    }

    #[test]
    fn tier2_roundtrip() {
        let (h, body) = make_request(Tier::Two, None);
        let cache = InMemoryReplayCache::new(300);
        let v = verify_request(
            &SesameConfig::default(),
            &provider(),
            &cache,
            &ctx(),
            &h,
            &body,
            now(),
            Tier::Two,
        )
        .expect("tier2 must verify");
        assert_eq!(v.scope_channel.as_deref(), Some("SportsFeed-East"));
        assert_eq!(v.achieved_tier, Tier::Two);
    }

    #[test]
    fn tier3_roundtrip_decrypts_to_original_xml() {
        let (h, body) = make_request(Tier::Three, None);
        let cache = InMemoryReplayCache::new(300);
        let v = verify_request(
            &SesameConfig::default(),
            &provider(),
            &cache,
            &ctx(),
            &h,
            &body,
            now(),
            Tier::Three,
        )
        .expect("tier3 must verify");
        // Schema-untouched: decrypted body is byte-for-byte the original ESAM XML.
        assert_eq!(v.plaintext, XML);
        assert_eq!(v.achieved_tier, Tier::Three);
    }

    #[test]
    fn tier0_passthrough_when_allowed() {
        let cache = InMemoryReplayCache::new(300);
        let h = SesameHeaders::default();
        let v = verify_request(
            &SesameConfig::default(),
            &provider(),
            &cache,
            &ctx(),
            &h,
            XML,
            now(),
            Tier::Zero,
        )
        .expect("tier0 passthrough");
        assert_eq!(v.achieved_tier, Tier::Zero);
        assert_eq!(v.plaintext, XML);
    }

    #[test]
    fn tier0_rejected_when_tier1_required() {
        let cache = InMemoryReplayCache::new(300);
        let h = SesameHeaders::default();
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &provider(),
                &cache,
                &ctx(),
                &h,
                XML,
                now(),
                Tier::One
            )
            .err(),
            Some(SesameError::MissingHeaders)
        );
    }

    // ---- negative matrix (handoff §8) ----

    #[test]
    fn tampered_body_rejected() {
        let (h, mut body) = make_request(Tier::One, None);
        body.extend_from_slice(b"<!-- injected -->");
        let cache = InMemoryReplayCache::new(300);
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &provider(),
                &cache,
                &ctx(),
                &h,
                &body,
                now(),
                Tier::One
            )
            .err(),
            Some(SesameError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_signed_header_rejected() {
        let (mut h, body) = make_request(Tier::One, None);
        h.nonce = Some("ffffffffffffffffffffffffffffffff".to_string()); // changes canonical
        let cache = InMemoryReplayCache::new(300);
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &provider(),
                &cache,
                &ctx(),
                &h,
                &body,
                now(),
                Tier::One
            )
            .err(),
            Some(SesameError::SignatureMismatch)
        );
    }

    #[test]
    fn replayed_nonce_rejected() {
        let (h, body) = make_request(Tier::One, None);
        let cache = InMemoryReplayCache::new(300);
        assert!(verify_request(
            &SesameConfig::default(),
            &provider(),
            &cache,
            &ctx(),
            &h,
            &body,
            now(),
            Tier::One
        )
        .is_ok());
        // Second identical request -> replay.
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &provider(),
                &cache,
                &ctx(),
                &h,
                &body,
                now(),
                Tier::One
            )
            .err(),
            Some(SesameError::ReplayDetected)
        );
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (h, body) = make_request(Tier::One, None);
        let cache = InMemoryReplayCache::new(300);
        let later = OffsetDateTime::parse("2026-02-24T18:10:00Z", &Rfc3339).unwrap(); // +600s
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &provider(),
                &cache,
                &ctx(),
                &h,
                &body,
                later,
                Tier::One
            )
            .err(),
            Some(SesameError::ExpiredTimestamp)
        );
    }

    #[test]
    fn unknown_key_rejected() {
        let (mut h, body) = make_request(Tier::One, None);
        h.key_id = Some("ghost".to_string());
        let cache = InMemoryReplayCache::new(300);
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &provider(),
                &cache,
                &ctx(),
                &h,
                &body,
                now(),
                Tier::One
            )
            .err(),
            Some(SesameError::UnknownKey)
        );
    }

    #[test]
    fn unauthorized_channel_rejected() {
        // Build a valid Tier-2 request but target/declare a channel the key can't use.
        let p = provider();
        let key = p.primary_signing_key("sas-east-01").unwrap().0;
        let timestamp = "2026-02-24T18:00:00Z";
        let nonce = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        let scope = "channel=PremiumFeed";
        let body_hash = canonical::body_hash_hex(XML);
        let canonical = canonical::request_canonical(
            "POST",
            "/esam?channel=PremiumFeed",
            timestamp,
            nonce,
            &body_hash,
            Some(scope),
        );
        let signature = tier1_hmac::sign(&key, &canonical);
        let h = SesameHeaders {
            version: Some(PROTOCOL_VERSION.to_string()),
            key_id: Some("sas-east-01".to_string()),
            timestamp: Some(timestamp.to_string()),
            nonce: Some(nonce.to_string()),
            signature: Some(signature),
            scope: Some(scope.to_string()),
            ..Default::default()
        };
        let ctx = RequestContext {
            method: "POST",
            path: "/esam?channel=PremiumFeed",
            target_channel: Some("PremiumFeed"),
        };
        let cache = InMemoryReplayCache::new(300);
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &p,
                &cache,
                &ctx,
                &h,
                XML,
                now(),
                Tier::Two
            )
            .err(),
            Some(SesameError::ScopeDenied)
        );
    }

    #[test]
    fn truncated_gcm_tag_rejected() {
        let (h, mut body) = make_request(Tier::Three, None);
        body.truncate(body.len() - 1); // damage the tag
        let cache = InMemoryReplayCache::new(300);
        let err = verify_request(
            &SesameConfig::default(),
            &provider(),
            &cache,
            &ctx(),
            &h,
            &body,
            now(),
            Tier::Three,
        )
        .err();
        assert_eq!(err, Some(SesameError::SignatureMismatch)); // body hash changes first
    }

    #[test]
    fn wrong_version_rejected() {
        let (mut h, body) = make_request(Tier::One, None);
        h.version = Some("2.0".to_string());
        let cache = InMemoryReplayCache::new(300);
        assert_eq!(
            verify_request(
                &SesameConfig::default(),
                &provider(),
                &cache,
                &ctx(),
                &h,
                &body,
                now(),
                Tier::One
            )
            .err(),
            Some(SesameError::InvalidVersion)
        );
    }

    #[test]
    fn response_sign_and_client_verify_roundtrip() {
        // POIS signs a response; a client re-derives the canonical string and
        // verifies it with the POIS public key-id. This is the forged-response
        // defense (the primary threat).
        let p = provider();
        let params = ResponseParams {
            signing_key_id: "pois-primary",
            correlation: "sig-20260224-001",
            scope: Some("channel=SportsFeed-East"),
            tier: Tier::Two,
            enc_key_id: None,
        };
        let resp = sign_response(&SesameConfig::default(), &p, &params, XML, now()).unwrap();

        // client side
        let get = |name: &str| {
            resp.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
        };
        let ts = get(message::H_TIMESTAMP).unwrap();
        let nonce = get(message::H_NONCE).unwrap();
        let sig = get(message::H_SIGNATURE).unwrap();
        let body_hash = canonical::body_hash_hex(&resp.body);
        let canonical = canonical::response_canonical(
            "sig-20260224-001",
            &ts,
            &nonce,
            &body_hash,
            Some("channel=SportsFeed-East"),
        );
        let key = p.primary_signing_key("pois-primary").unwrap().0;
        assert!(tier1_hmac::verify(&key, &canonical, &sig).is_ok());
    }

    #[test]
    fn forged_response_detected() {
        let p = provider();
        let params = ResponseParams {
            signing_key_id: "pois-primary",
            correlation: "sig-1",
            scope: None,
            tier: Tier::One,
            enc_key_id: None,
        };
        let resp = sign_response(&SesameConfig::default(), &p, &params, XML, now()).unwrap();
        let get = |name: &str| {
            resp.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
        };
        let ts = get(message::H_TIMESTAMP).unwrap();
        let nonce = get(message::H_NONCE).unwrap();
        let sig = get(message::H_SIGNATURE).unwrap();
        // Attacker swaps the decision body.
        let forged = b"<SignalProcessingNotification action=\"blackout\"/>";
        let body_hash = canonical::body_hash_hex(forged);
        let canonical = canonical::response_canonical("sig-1", &ts, &nonce, &body_hash, None);
        let key = p.primary_signing_key("pois-primary").unwrap().0;
        assert!(tier1_hmac::verify(&key, &canonical, &sig).is_err());
    }

    #[test]
    fn response_iv_differs_from_request_iv() {
        // Regression for the Appendix A.4 crypto bug (errata E1 / [BO-4]): a
        // response MUST NOT reuse the request's GCM IV under the same EncKeyId.
        let (req_headers, _req_body) = make_request(Tier::Three, None);
        let req_iv = req_headers.iv.clone().unwrap();

        let p = provider();
        let params = ResponseParams {
            signing_key_id: "pois-primary",
            correlation: "sig-001",
            scope: Some("channel=SportsFeed-East"),
            tier: Tier::Three,
            enc_key_id: Some("enc-sportsfeed-2026q1"), // same key as the request
        };
        let resp = sign_response(&SesameConfig::default(), &p, &params, XML, now()).unwrap();
        let resp_iv = resp
            .headers
            .iter()
            .find(|(k, _)| *k == message::H_IV)
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_ne!(
            req_iv, resp_iv,
            "response reused the request IV under the same EncKeyId"
        );
    }

    #[test]
    fn tier3_response_uses_fresh_iv() {
        let p = provider();
        let params = ResponseParams {
            signing_key_id: "pois-primary",
            correlation: "sig-1",
            scope: Some("channel=SportsFeed-East"),
            tier: Tier::Three,
            enc_key_id: Some("enc-sportsfeed-2026q1"),
        };
        let r1 = sign_response(&SesameConfig::default(), &p, &params, XML, now()).unwrap();
        let r2 = sign_response(&SesameConfig::default(), &p, &params, XML, now()).unwrap();
        let iv = |r: &SignedResponse| {
            r.headers
                .iter()
                .find(|(k, _)| *k == message::H_IV)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_ne!(iv(&r1), iv(&r2), "each response MUST use a fresh GCM IV");
        assert_eq!(r1.content_type, "application/octet-stream");
    }
}
