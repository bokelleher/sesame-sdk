//! Conformance gate: the golden vectors in `test-vectors/` (generated from the
//! deployed `rust-pois` implementation) MUST be reproduced byte-for-byte by this
//! crate. This is the proof that the SDK is a faithful extraction of the
//! deployed wire format, not a parallel reimplementation that has drifted.
//!
//! Requires the `serde` feature (for the vector types). Run:
//!   cargo test --features serde --test conformance

#![cfg(feature = "serde")]

use sesame::canonical::{body_hash_hex, request_canonical, response_canonical};
use sesame::message::{hex_decode, hex_encode};
use sesame::tier1_hmac::sign;
use sesame::tier3_aead::{aad_for_headers, open, seal, IV_LEN, KEY_LEN};
use sesame::vectors::{Tier1File, Tier3File};

fn read(path: &str) -> String {
    let full = format!("{}/test-vectors/{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {full}: {e}"))
}

fn key32(hex: &str) -> [u8; KEY_LEN] {
    let v = hex_decode(hex).expect("enc key hex");
    let mut k = [0u8; KEY_LEN];
    assert_eq!(v.len(), KEY_LEN, "enc key must be 32 bytes");
    k.copy_from_slice(&v);
    k
}

fn iv12(hex: &str) -> [u8; IV_LEN] {
    let v = hex_decode(hex).expect("iv hex");
    let mut iv = [0u8; IV_LEN];
    assert_eq!(v.len(), IV_LEN, "iv must be 12 bytes");
    iv.copy_from_slice(&v);
    iv
}

#[test]
fn tier1_request_vectors_reproduce() {
    let file: Tier1File = serde_json::from_str(&read("tier1.json")).expect("parse tier1.json");
    assert!(!file.request_vectors.is_empty(), "no request vectors");

    for v in &file.request_vectors {
        let body = hex_decode(&v.body_hex).expect("body hex");
        let bh = body_hash_hex(&body);
        let canonical = request_canonical(
            &v.method,
            &v.path,
            &v.timestamp,
            &v.nonce,
            &bh,
            v.scope.as_deref(),
        );
        assert_eq!(
            canonical, v.expected_canonical,
            "request canonical mismatch for {:?}",
            v.name
        );

        let key = hex_decode(&v.signing_key_hex).expect("key hex");
        let signature = sign(&key, &canonical);
        assert_eq!(
            signature, v.expected_signature_hex,
            "request signature mismatch for {:?}",
            v.name
        );
    }
}

#[test]
fn tier1_response_vectors_reproduce() {
    let file: Tier1File = serde_json::from_str(&read("tier1.json")).expect("parse tier1.json");
    assert!(!file.response_vectors.is_empty(), "no response vectors");

    for v in &file.response_vectors {
        let body = hex_decode(&v.body_hex).expect("body hex");
        let bh = body_hash_hex(&body);
        let canonical = response_canonical(
            &v.correlation,
            &v.timestamp,
            &v.nonce,
            &bh,
            v.scope.as_deref(),
        );
        assert_eq!(
            canonical, v.expected_canonical,
            "response canonical mismatch for {:?}",
            v.name
        );

        let key = hex_decode(&v.signing_key_hex).expect("key hex");
        let signature = sign(&key, &canonical);
        assert_eq!(
            signature, v.expected_signature_hex,
            "response signature mismatch for {:?}",
            v.name
        );
    }
}

#[test]
fn tier3_aead_vectors_reproduce() {
    let file: Tier3File = serde_json::from_str(&read("tier3.json")).expect("parse tier3.json");
    assert!(!file.aead_vectors.is_empty(), "no aead vectors");

    for v in &file.aead_vectors {
        let aad = aad_for_headers(
            &v.version,
            &v.key_id,
            &v.timestamp,
            &v.nonce,
            v.scope.as_deref(),
        );
        assert_eq!(
            String::from_utf8(aad.clone()).unwrap(),
            v.expected_aad_utf8,
            "aad mismatch for {:?}",
            v.name
        );

        let key = key32(&v.enc_key_hex);
        let iv = iv12(&v.iv_hex);
        let plaintext = hex_decode(&v.plaintext_hex).expect("plaintext hex");
        let body = seal(&key, &iv, &aad, &plaintext).expect("seal");
        assert_eq!(
            hex_encode(&body),
            v.expected_body_hex,
            "ciphertext||tag mismatch for {:?}",
            v.name
        );

        // round-trips back to plaintext
        let recovered = open(&key, &iv, &aad, &body).expect("open");
        assert_eq!(recovered, plaintext, "decrypt round-trip for {:?}", v.name);
    }
}
