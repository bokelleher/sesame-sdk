// Golden-vector extractor.
//
// Calls rust-pois's deterministic SESAME functions (copied verbatim into
// src/sesame/) with fixed inputs and emits JSON conformance vectors. These are
// the authoritative cross-implementation contract: the `sesame` crate must
// reproduce every `expected_*` value byte-for-byte.

mod sesame;

use sesame::canonical::{body_hash_hex, request_canonical, response_canonical};
use sesame::message::{hex_decode, hex_encode};
use sesame::tier1_hmac::sign;
use sesame::tier3_aead::{aad_for_headers, seal, IV_LEN, KEY_LEN};
use serde_json::{json, Value};

// Fixed, deterministic inputs.
const SIGNING_KEY_HEX: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
const ENC_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IV_HEX: &str = "a0a1a2a3a4a5a6a7a8a9aaab";
const TS: &str = "2026-02-24T18:00:00Z";
const NONCE: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
const VERSION: &str = "1.0";
const KEY_ID: &str = "sas-east-01";
const SCOPE: &str = "channel=SportsFeed-East";
const CORRELATION: &str = "ap-1:sigid-20260224-001";

const NOTE: &str = "Golden vectors generated from the rust-pois deployed implementation \
(src/sesame/, ANSI/SCTE 130-9 SESAME draft v0.5). Authoritative cross-implementation \
contract: the sesame crate MUST reproduce every expected_* value byte-for-byte. \
Regenerate with tools/golden-extractor against rust-pois.";

fn enc_key() -> [u8; KEY_LEN] {
    let v = hex_decode(ENC_KEY_HEX).unwrap();
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&v);
    k
}
fn iv() -> [u8; IV_LEN] {
    let v = hex_decode(IV_HEX).unwrap();
    let mut x = [0u8; IV_LEN];
    x.copy_from_slice(&v);
    x
}

fn req_vector(
    name: &str,
    method: &str,
    path: &str,
    scope: Option<&str>,
    body: &[u8],
    body_utf8: Option<&str>,
    encrypted: bool,
) -> Value {
    let key = hex_decode(SIGNING_KEY_HEX).unwrap();
    let bh = body_hash_hex(body);
    let canonical = request_canonical(method, path, TS, NONCE, &bh, scope);
    let signature = sign(&key, &canonical);
    json!({
        "name": name,
        "method": method,
        "path": path,
        "timestamp": TS,
        "nonce": NONCE,
        "scope": scope,
        "signing_key_hex": SIGNING_KEY_HEX,
        "body_hex": hex_encode(body),
        "body_utf8": body_utf8,
        "body_is_encrypted": encrypted,
        "expected_canonical": canonical,
        "expected_signature_hex": signature,
    })
}

fn resp_vector(name: &str, scope: Option<&str>, body: &[u8], body_utf8: &str) -> Value {
    let key = hex_decode(SIGNING_KEY_HEX).unwrap();
    let bh = body_hash_hex(body);
    let canonical = response_canonical(CORRELATION, TS, NONCE, &bh, scope);
    let signature = sign(&key, &canonical);
    json!({
        "name": name,
        "correlation": CORRELATION,
        "timestamp": TS,
        "nonce": NONCE,
        "scope": scope,
        "signing_key_hex": SIGNING_KEY_HEX,
        "body_hex": hex_encode(body),
        "body_utf8": body_utf8,
        "expected_canonical": canonical,
        "expected_signature_hex": signature,
    })
}

fn aead_vector(name: &str, scope: Option<&str>, plaintext: &[u8], plaintext_utf8: &str) -> Value {
    let aad = aad_for_headers(VERSION, KEY_ID, TS, NONCE, scope);
    let body = seal(&enc_key(), &iv(), &aad, plaintext).unwrap();
    json!({
        "name": name,
        "enc_key_hex": ENC_KEY_HEX,
        "iv_hex": IV_HEX,
        "version": VERSION,
        "key_id": KEY_ID,
        "timestamp": TS,
        "nonce": NONCE,
        "scope": scope,
        "plaintext_hex": hex_encode(plaintext),
        "plaintext_utf8": plaintext_utf8,
        "expected_aad_utf8": String::from_utf8(aad).unwrap(),
        "expected_body_hex": hex_encode(&body),
    })
}

fn main() {
    let xml = b"<SignalProcessingNotification acquisitionPointIdentity=\"ap-1\"/>";
    let xml_s = "<SignalProcessingNotification acquisitionPointIdentity=\"ap-1\"/>";
    let resp_xml = b"<SignalProcessingNotificationResponse acquisitionSignalID=\"ap-1:sigid-20260224-001\"/>";
    let resp_s = "<SignalProcessingNotificationResponse acquisitionSignalID=\"ap-1:sigid-20260224-001\"/>";

    // Tier 3 ciphertext (no scope) reused as the body of the encrypt-then-MAC request.
    let aad_ns = aad_for_headers(VERSION, KEY_ID, TS, NONCE, None);
    let ct_ns = seal(&enc_key(), &iv(), &aad_ns, xml).unwrap();

    let tier1 = json!({
        "note": NOTE,
        "request_vectors": [
            req_vector("tier1 request, no scope", "POST", "/esam", None, xml, Some(xml_s), false),
            req_vector("tier2 request, scope in path and signed", "POST",
                       "/esam?channel=SportsFeed-East", Some(SCOPE), xml, Some(xml_s), false),
            req_vector("tier1 request, empty body", "POST", "/esam", None, b"", Some(""), false),
            req_vector("tier3 request, signature over ciphertext||tag (encrypt-then-MAC)",
                       "POST", "/esam", None, &ct_ns, None, true),
        ],
        "response_vectors": [
            resp_vector("response, no scope", None, resp_xml, resp_s),
            resp_vector("response, with scope", Some(SCOPE), resp_xml, resp_s),
        ],
    });

    let tier3 = json!({
        "note": NOTE,
        "aead_vectors": [
            aead_vector("tier3 aead, no scope", None, xml, xml_s),
            aead_vector("tier3 aead, scope bound in AAD", Some(SCOPE), xml, xml_s),
            aead_vector("tier3 aead, empty plaintext", None, b"", ""),
        ],
    });

    let out = "/opt/sesame-sdk/test-vectors";
    std::fs::write(
        format!("{out}/tier1.json"),
        serde_json::to_string_pretty(&tier1).unwrap() + "\n",
    )
    .unwrap();
    std::fs::write(
        format!("{out}/tier3.json"),
        serde_json::to_string_pretty(&tier3).unwrap() + "\n",
    )
    .unwrap();
    println!("wrote {out}/tier1.json and {out}/tier3.json");
}
