//! Error types for the SESAME core.
//!
//! Everything here is I/O-free and allocation-light. Variants carry just enough
//! context to diagnose a rejection without leaking secrets (never the key, never
//! the expected signature).

use core::fmt;

/// A replay was detected by the host's [`NonceStore`](crate::traits::NonceStore).
///
/// Kept as its own zero-sized type (rather than only a [`SesameError`] variant)
/// so the storage seam stays narrow: a `NonceStore` impl only ever has to say
/// "fresh" or "seen", and never has to construct a richer error. It converts
/// into [`SesameError::Replay`] via [`From`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replay;

impl fmt::Display for Replay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("nonce replay detected")
    }
}

impl std::error::Error for Replay {}

/// Everything that can go wrong verifying (or constructing) a SESAME exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SesameError {
    /// A required header was absent.
    MissingHeader(&'static str),
    /// A header was present but could not be parsed (bad base64, non-numeric
    /// timestamp, wrong length, etc.). `reason` is a stable, non-secret hint.
    MalformedHeader {
        header: &'static str,
        reason: &'static str,
    },
    /// `X-Sesame-Version` named a version this build does not implement.
    UnsupportedVersion(String),
    /// Tier 3 named an encryption suite this build does not implement.
    UnsupportedEncryption(String),
    /// The key id did not resolve to a key (tier 1/2).
    UnknownKey(String),
    /// The HMAC did not match. Constant-time comparison; carries no detail.
    SignatureMismatch,
    /// The timestamp was outside the freshness window. `skew_secs` is
    /// `now - timestamp` (may be negative for future-dated requests).
    Stale { skew_secs: i64, window_secs: u64 },
    /// The nonce was seen before within the window.
    Replay,
    /// Tier 2: the resolved key is not authorized for the named channel.
    Unauthorized { channel: String },
    /// Tier 3: GCM authentication/decryption failed.
    Decryption,
    /// Tier 3: GCM encryption could not be performed (e.g. wrong key length).
    Encryption,
}

impl fmt::Display for SesameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SesameError::*;
        match self {
            MissingHeader(h) => write!(f, "missing required header {h}"),
            MalformedHeader { header, reason } => {
                write!(f, "malformed header {header}: {reason}")
            }
            UnsupportedVersion(v) => write!(f, "unsupported SESAME version {v:?}"),
            UnsupportedEncryption(e) => write!(f, "unsupported encryption suite {e:?}"),
            UnknownKey(id) => write!(f, "unknown key id {id:?}"),
            SignatureMismatch => f.write_str("signature mismatch"),
            Stale {
                skew_secs,
                window_secs,
            } => write!(
                f,
                "stale request: clock skew {skew_secs}s exceeds ±{window_secs}s window"
            ),
            Replay => f.write_str("nonce replay detected"),
            Unauthorized { channel } => write!(f, "key not authorized for channel {channel:?}"),
            Decryption => f.write_str("payload decryption/authentication failed"),
            Encryption => f.write_str("payload encryption failed"),
        }
    }
}

impl std::error::Error for SesameError {}

impl From<Replay> for SesameError {
    fn from(_: Replay) -> Self {
        SesameError::Replay
    }
}
