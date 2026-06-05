//! Deserialization shapes for the golden conformance vectors (feature `serde`).
//!
//! The JSON in `test-vectors/` is generated from the deployed `rust-pois`
//! implementation (see `tools/golden-extractor`). It is the authoritative
//! cross-implementation contract: `tests/conformance.rs` reconstructs each
//! input and asserts this crate reproduces every `expected_*` value
//! byte-for-byte. Nothing here is Rust-specific; the fields are scalars and
//! hex/utf-8 strings any implementation can consume.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Tier1File {
    pub note: String,
    pub request_vectors: Vec<RequestVector>,
    pub response_vectors: Vec<ResponseVector>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestVector {
    pub name: String,
    pub method: String,
    pub path: String,
    pub timestamp: String,
    pub nonce: String,
    pub scope: Option<String>,
    pub signing_key_hex: String,
    pub body_hex: String,
    pub body_utf8: Option<String>,
    pub body_is_encrypted: bool,
    pub expected_canonical: String,
    pub expected_signature_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseVector {
    pub name: String,
    pub correlation: String,
    pub timestamp: String,
    pub nonce: String,
    pub scope: Option<String>,
    pub signing_key_hex: String,
    pub body_hex: String,
    pub body_utf8: Option<String>,
    pub expected_canonical: String,
    pub expected_signature_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tier3File {
    pub note: String,
    pub aead_vectors: Vec<AeadVector>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AeadVector {
    pub name: String,
    pub enc_key_hex: String,
    pub iv_hex: String,
    pub version: String,
    pub key_id: String,
    pub timestamp: String,
    pub nonce: String,
    pub scope: Option<String>,
    pub plaintext_hex: String,
    pub plaintext_utf8: Option<String>,
    pub expected_aad_utf8: String,
    pub expected_body_hex: String,
}
