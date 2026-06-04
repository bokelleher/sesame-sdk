//! Conformance gate: the committed `test-vectors/*.json` MUST be reproduced
//! byte-for-byte by the current implementation.
//!
//! This is the in-repo guard against drift. A cross-language implementer uses
//! the same JSON the other direction (read inputs → assert they reproduce
//! `expected_*`). If anyone changes the canonical signing string or the GCM
//! binding without regenerating the vectors, this test fails — which is the
//! point: the published contract may only change deliberately.
//!
//! Requires the `serde` feature (for the vector types). Run:
//!   cargo test --features serde --test conformance

#![cfg(feature = "serde")]

use sesame::canonical::Canonical;
use sesame::cipher;
use sesame::encoding::{b64_encode, hex_decode, hex_encode};
use sesame::types::{ChannelScope, Key, KeyId, Nonce, RequestParts, UnixTime};
use sesame::vectors::{GcmVectorFile, SigningVectorFile};

fn read(path: &str) -> String {
    let full = format!("{}/test-vectors/{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {full}: {e}"))
}

#[test]
fn signing_vectors_reproduce() {
    let file: SigningVectorFile =
        serde_json::from_str(&read("signing.json")).expect("parse signing.json");
    assert!(!file.vectors.is_empty(), "no signing vectors committed");

    for v in &file.vectors {
        let key = Key(hex_decode(&v.key_hex).expect("key hex"));
        let nonce = Nonce(hex_decode(&v.nonce_hex).expect("nonce hex"));
        let key_id = KeyId(v.key_id.clone());
        let channel = v.channel.clone().map(ChannelScope);

        // 1. canonical signing string reproduces exactly
        let signing_string = Canonical {
            version: &v.version,
            method: &v.method,
            target: &v.target,
            key_id: &key_id,
            timestamp: UnixTime(v.timestamp),
            nonce: &nonce,
            channel: channel.as_ref(),
            body: v.body_utf8.as_bytes(),
        }
        .to_signing_string();
        assert_eq!(
            signing_string, v.expected_signing_string,
            "signing string mismatch for {:?}",
            v.description
        );

        // 2. HMAC reproduces, via the public sign() path
        let parts = RequestParts {
            method: &v.method,
            target: &v.target,
            key_id: key_id.clone(),
            channel: channel.clone(),
        };
        let signed = sesame::sign(
            &parts,
            &key,
            &nonce,
            UnixTime(v.timestamp),
            v.body_utf8.as_bytes(),
            None,
        )
        .expect("sign");
        assert_eq!(
            signed.header(sesame::header::SIGNATURE).unwrap(),
            v.expected_signature_b64,
            "signature mismatch for {:?}",
            v.description
        );

        // 3. the signed message verifies
        let verified =
            sesame::verify_signature(&v.method, &v.target, &signed.headers, &signed.body, &key)
                .expect("verify");
        assert_eq!(verified.key_id, key_id);
        assert_eq!(verified.channel, channel);
    }
}

#[test]
fn gcm_vectors_reproduce() {
    let file: GcmVectorFile = serde_json::from_str(&read("gcm.json")).expect("parse gcm.json");
    assert!(!file.vectors.is_empty(), "no gcm vectors committed");

    for v in &file.vectors {
        let key = hex_decode(&v.key_hex).expect("key hex");
        let iv_vec = hex_decode(&v.iv_hex).expect("iv hex");
        let iv: [u8; 12] = iv_vec.try_into().expect("iv is 12 bytes");
        let key_id = KeyId(v.key_id.clone());
        let nonce = Nonce(hex_decode(&v.nonce_hex).expect("nonce hex"));
        let channel = v.channel.clone().map(ChannelScope);

        let aad = cipher::associated_data(&key_id, UnixTime(v.timestamp), &nonce, channel.as_ref());
        assert_eq!(
            String::from_utf8(aad).unwrap(),
            v.aad_utf8,
            "aad mismatch for {:?}",
            v.description
        );

        let (ciphertext, tag) = cipher::encrypt(
            &key,
            &iv,
            &key_id,
            UnixTime(v.timestamp),
            &nonce,
            channel.as_ref(),
            v.plaintext_utf8.as_bytes(),
        )
        .expect("encrypt");
        assert_eq!(
            hex_encode(&ciphertext),
            v.expected_ciphertext_hex,
            "ciphertext mismatch for {:?}",
            v.description
        );
        assert_eq!(
            b64_encode(&tag),
            v.expected_tag_b64,
            "tag mismatch for {:?}",
            v.description
        );

        // round-trip back to plaintext
        let pt = cipher::decrypt(
            &key,
            &iv,
            &tag,
            &key_id,
            UnixTime(v.timestamp),
            &nonce,
            channel.as_ref(),
            &ciphertext,
        )
        .expect("decrypt");
        assert_eq!(pt, v.plaintext_utf8.as_bytes());
    }
}
