//! Serde shapes for the language-neutral conformance vectors (feature `serde`).
//!
//! These structs ARE the cross-language contract: a Go/Python/C++ implementer
//! reads `test-vectors/*.json`, reconstructs the inputs from the hex/utf-8
//! fields, and asserts they reproduce `expected_*`. Nothing here is
//! Rust-specific, the fields are plain scalars and hex/base64 strings.

use serde::{Deserialize, Serialize};

/// A tier 1 (canonical signing string + HMAC) conformance case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningVector {
    pub description: String,
    pub version: String,
    pub method: String,
    pub target: String,
    pub key_id: String,
    /// HMAC key, hex-encoded.
    pub key_hex: String,
    pub timestamp: u64,
    /// Anti-replay nonce, hex-encoded.
    pub nonce_hex: String,
    /// Tier 2 channel scope, or `null` when absent.
    pub channel: Option<String>,
    /// Request body as UTF-8 (these vectors use text bodies for readability).
    pub body_utf8: String,
    /// The exact canonical signing string (LF-separated, no trailing newline).
    pub expected_signing_string: String,
    /// base64(HMAC-SHA256(key, signing_string)).
    pub expected_signature_b64: String,
}

/// A tier 3 (AES-256-GCM) conformance case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcmVector {
    pub description: String,
    /// 32-byte AES-256 key, hex-encoded.
    pub key_hex: String,
    /// 12-byte GCM IV, hex-encoded.
    pub iv_hex: String,
    pub key_id: String,
    pub timestamp: u64,
    pub nonce_hex: String,
    pub channel: Option<String>,
    pub plaintext_utf8: String,
    /// The associated data bound by GCM, as UTF-8 (derivable, included for
    /// cross-impl debugging).
    pub aad_utf8: String,
    /// Ciphertext (tag stripped), hex-encoded.
    pub expected_ciphertext_hex: String,
    /// base64 of the 16-byte GCM tag.
    pub expected_tag_b64: String,
}

/// Top-level shape of each committed vector file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningVectorFile {
    pub note: String,
    pub vectors: Vec<SigningVector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcmVectorFile {
    pub note: String,
    pub vectors: Vec<GcmVector>,
}
