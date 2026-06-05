// src/sesame/message.rs
//
// SESAME header names, the parsed `SesameHeaders` view, the error taxonomy
// (matching the paper's Appendix A.7 error-code table), and small hex helpers.
//
// Spec source of truth: ANSI/SCTE 130-9 (SESAME) draft v0.5, §8.2 and Appendix A.
// Where this code resolves a gap or contradiction in the draft, the comment is
// tagged `[BO]` and the decision is recorded in docs/SESAME_reconciliation.md.

// -------------------------------------------------------------------------
// Header names (Appendix A.6, "SESAME Header Reference")
// -------------------------------------------------------------------------

pub const H_VERSION: &str = "X-SESAME-Version";
pub const H_KEY_ID: &str = "X-SESAME-KeyId";
pub const H_TIMESTAMP: &str = "X-SESAME-Timestamp";
pub const H_NONCE: &str = "X-SESAME-Nonce";
pub const H_SIGNATURE: &str = "X-SESAME-Signature";
pub const H_SCOPE: &str = "X-SESAME-Scope";
pub const H_ENCRYPTED: &str = "X-SESAME-Encrypted";
pub const H_ENC_KEY_ID: &str = "X-SESAME-EncKeyId";
pub const H_IV: &str = "X-SESAME-IV";

/// The protocol version this implementation speaks (paper §8.2: `X-SESAME-Version: 1.0`).
pub const PROTOCOL_VERSION: &str = "1.0";

// -------------------------------------------------------------------------
// Error taxonomy (Appendix A.7, "SESAME Error Codes")
// -------------------------------------------------------------------------

/// Every distinct SESAME failure, fail-closed. Each maps 1:1 to a wire error
/// code and HTTP status from Appendix A.7.
///
/// NOTE for [BO]: the draft distinguishes `sesame_unknown_key` from
/// `sesame_signature_mismatch` (both 401). That is a mild key-enumeration
/// oracle and conflicts with the handoff's "no-leak" goal. We follow the paper
/// (distinct codes) but expose `http_status()` so an operator can collapse
/// them to a single opaque 401 if desired. See reconciliation note item 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SesameError {
    MissingHeaders,
    InvalidVersion,
    UnknownKey,
    ExpiredTimestamp,
    ReplayDetected,
    SignatureMismatch,
    ScopeDenied,
    DecryptFailed,
    KeyRevoked,
}

impl SesameError {
    /// Stable wire error code (Appendix A.7, first column).
    pub fn code(&self) -> &'static str {
        match self {
            SesameError::MissingHeaders => "sesame_missing_headers",
            SesameError::InvalidVersion => "sesame_invalid_version",
            SesameError::UnknownKey => "sesame_unknown_key",
            SesameError::ExpiredTimestamp => "sesame_expired_timestamp",
            SesameError::ReplayDetected => "sesame_replay_detected",
            SesameError::SignatureMismatch => "sesame_signature_mismatch",
            SesameError::ScopeDenied => "sesame_scope_denied",
            SesameError::DecryptFailed => "sesame_decrypt_failed",
            SesameError::KeyRevoked => "sesame_key_revoked",
        }
    }

    /// HTTP status (Appendix A.7, second column).
    pub fn http_status(&self) -> u16 {
        match self {
            SesameError::InvalidVersion | SesameError::DecryptFailed => 400,
            SesameError::ScopeDenied => 403,
            _ => 401,
        }
    }
}

impl core::fmt::Display for SesameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::error::Error for SesameError {}

// -------------------------------------------------------------------------
// Parsed header view
// -------------------------------------------------------------------------

/// The SESAME headers extracted from a request or response. Timestamp, nonce,
/// signature and IV are kept as their exact on-wire string forms because the
/// signature is computed over those exact bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SesameHeaders {
    pub version: Option<String>,
    pub key_id: Option<String>,
    pub timestamp: Option<String>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
    pub scope: Option<String>,
    pub encrypted: bool,
    pub enc_key_id: Option<String>,
    pub iv: Option<String>,
}

impl SesameHeaders {
    /// True when none of the Tier-1 headers are present, i.e. an unauthenticated
    /// (Tier 0) request, permitted only when the channel policy allows it (§9.3).
    pub fn is_absent(&self) -> bool {
        self.version.is_none()
            && self.key_id.is_none()
            && self.timestamp.is_none()
            && self.nonce.is_none()
            && self.signature.is_none()
    }

    /// Parse from any header source via a case-insensitive lookup closure.
    /// Framework-agnostic: the axum adapter passes a closure over `HeaderMap`.
    pub fn from_lookup<F>(get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let encrypted = get(H_ENCRYPTED)
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        SesameHeaders {
            version: get(H_VERSION),
            key_id: get(H_KEY_ID),
            timestamp: get(H_TIMESTAMP),
            nonce: get(H_NONCE),
            signature: get(H_SIGNATURE),
            scope: get(H_SCOPE),
            encrypted,
            enc_key_id: get(H_ENC_KEY_ID),
            iv: get(H_IV),
        }
    }

    /// Tier-1 headers required on every authenticated message. Returns the
    /// fields or `MissingHeaders` if any are absent.
    pub fn require_tier1(&self) -> Result<Tier1Fields<'_>, SesameError> {
        match (
            self.version.as_deref(),
            self.key_id.as_deref(),
            self.timestamp.as_deref(),
            self.nonce.as_deref(),
            self.signature.as_deref(),
        ) {
            (Some(version), Some(key_id), Some(timestamp), Some(nonce), Some(signature)) => {
                Ok(Tier1Fields {
                    version,
                    key_id,
                    timestamp,
                    nonce,
                    signature,
                })
            }
            _ => Err(SesameError::MissingHeaders),
        }
    }
}

/// Borrowed view of the mandatory Tier-1 fields after presence validation.
pub struct Tier1Fields<'a> {
    pub version: &'a str,
    pub key_id: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub signature: &'a str,
}

// -------------------------------------------------------------------------
// Hex helpers (lowercase, per the paper, nonces/signatures/IVs are hex)
// -------------------------------------------------------------------------

pub fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        let hi = val(bytes[i])?;
        let lo = val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0x00u8, 0x0f, 0xa1, 0xff, 0x10];
        assert_eq!(hex_encode(&data), "000fa1ff10");
        assert_eq!(hex_decode("000fa1ff10").unwrap(), data);
    }

    #[test]
    fn hex_decode_rejects_odd_and_nonhex() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn absent_headers_detected() {
        assert!(SesameHeaders::default().is_absent());
    }

    #[test]
    fn error_codes_and_statuses_match_appendix() {
        assert_eq!(SesameError::ScopeDenied.code(), "sesame_scope_denied");
        assert_eq!(SesameError::ScopeDenied.http_status(), 403);
        assert_eq!(SesameError::DecryptFailed.http_status(), 400);
        assert_eq!(SesameError::InvalidVersion.http_status(), 400);
        assert_eq!(SesameError::ReplayDetected.http_status(), 401);
    }
}
