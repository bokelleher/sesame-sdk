//! Wire types shared by signer and verifier.
//!
//! These are deliberately small newtypes over owned data so the core has no
//! lifetime entanglement with any particular HTTP framework. The `serde`
//! feature adds derives used by the conformance harness and CLI; the types
//! themselves do not depend on serde.

use core::fmt;

/// Protocol version this build implements, as it appears in `X-Sesame-Version`.
pub const VERSION: &str = "1";

/// The only encryption suite defined for tier 3 in v1.
pub const ENC_AES_256_GCM: &str = "AES-256-GCM";

/// Canonical HTTP header names. Comparisons against incoming headers MUST be
/// case-insensitive (HTTP header names are case-insensitive); these are the
/// canonical spellings a signer emits.
pub mod header {
    pub const VERSION: &str = "X-Sesame-Version";
    pub const KEY_ID: &str = "X-Sesame-Key-Id";
    pub const TIMESTAMP: &str = "X-Sesame-Timestamp";
    pub const NONCE: &str = "X-Sesame-Nonce";
    pub const CHANNEL: &str = "X-Sesame-Channel";
    pub const SIGNATURE: &str = "X-Sesame-Signature";
    pub const ENCRYPTION: &str = "X-Sesame-Encryption";
    pub const IV: &str = "X-Sesame-IV";
    pub const TAG: &str = "X-Sesame-Tag";
}

/// Seconds since the Unix epoch. The wire encoding is decimal ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(pub u64);

impl UnixTime {
    #[inline]
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

/// Opaque identifier for the signing key. Maps (via a
/// [`KeyResolver`](crate::traits::KeyResolver)) to a key and an authorization
/// scope on the verifying side.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(pub String);

/// Tier 2 authorization scope — the channel the request is acting on.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelScope(pub String);

/// Anti-replay nonce: raw random bytes (RECOMMENDED ≥ 16). Carried base64 in
/// `X-Sesame-Nonce`. Distinct from the GCM IV used by tier 3.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Nonce(pub Vec<u8>);

impl Nonce {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({} bytes)", self.0.len())
    }
}

/// A signing/verifying key. For tier 1 HMAC the length is unconstrained; for
/// tier 3 AES-256-GCM it MUST be exactly 32 bytes.
///
/// `Debug` is redacted so keys never land in logs by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(pub Vec<u8>);

impl Key {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// The request context that is bound by the signature.
///
/// `method` and `target` (request-target: path plus optional `?query`) are
/// included so a captured signature cannot be replayed against a different
/// endpoint. `body` is the bytes as transmitted — i.e. ciphertext when tier 3
/// is in use.
#[derive(Clone, Debug)]
pub struct RequestParts<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub key_id: KeyId,
    /// Tier 2: present when the request is channel-scoped.
    pub channel: Option<ChannelScope>,
}

/// Tier 3 encryption parameters supplied by the caller at sign time. The 12-byte
/// IV MUST be unique per (key, message); the caller owns IV generation so the
/// core stays free of any RNG dependency.
#[derive(Clone, Copy, Debug)]
pub struct EncryptionParams {
    pub iv: [u8; 12],
}

/// Tier 3 details recovered from the headers at verify time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionInfo {
    pub suite: String,
    pub iv: [u8; 12],
    pub tag: [u8; 16],
}

/// One `(name, value)` HTTP header pair. Values are already wire-encoded
/// (base64 / decimal ASCII).
pub type HeaderPair = (&'static str, String);

/// The output of [`sign`](crate::sign): the SESAME headers to attach, plus the
/// body to transmit (ciphertext under tier 3, otherwise the plaintext echoed
/// back unchanged).
#[derive(Clone, Debug)]
pub struct Signed {
    pub headers: Vec<HeaderPair>,
    pub body: Vec<u8>,
}

impl Signed {
    /// Look up a produced header value by canonical name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The trustworthy facts established by [`verify_signature`](crate::verify_signature):
/// the signature matched, so these header values are authentic. Freshness and
/// replay are *not* yet checked — that is the host's next step (see crate docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub key_id: KeyId,
    pub timestamp: UnixTime,
    pub nonce: Nonce,
    pub channel: Option<ChannelScope>,
    /// Present iff tier 3 was used; needed to decrypt the body.
    pub encryption: Option<EncryptionInfo>,
}
