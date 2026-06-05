//! examples/sign_request.rs, a self-contained SESAME client.
//!
//! Builds and sends Tier 1 / 2 / 3 ESAM requests to a POIS/ESAM endpoint, signing
//! (and for Tier 3 AEAD-encrypting) them with this crate's own primitives. Each
//! request is first self-checked against [`sesame::verify_request`], the very
//! verifier a server runs, so a failure points at the request construction, not
//! the network. It doubles as living documentation of the client side of the
//! protocol (the crate ships the server/verify side; this is the signer side).
//!
//! Run:
//! ```text
//! SESAME_KEYS=keys.json \
//! SESAME_URL=http://127.0.0.1:3090 \
//! SESAME_CHANNEL=default \
//! cargo run --example sign_request
//! ```
//!
//! `keys.json` is flat hex (field aliases accepted so an existing rust-pois
//! `sesame-keys.json` works unchanged):
//! ```json
//! { "signing_secret_hex": "<64 hex = 32-byte HMAC key>",   // alias: sas_secret_hex
//!   "enc_key_hex":        "<64 hex = 32-byte AES-256 key>" } // alias: encryption_key_hex
//! ```
//!
//! Env (all optional except SESAME_KEYS):
//!   SESAME_KEYS         path to the keys json (required)
//!   SESAME_URL          target base url            (default http://127.0.0.1:3090)
//!   SESAME_CHANNEL      channel for /esam?channel= (default "default")
//!   SESAME_KEY_ID       signing key id             (default "sas-east-01")
//!   SESAME_ENC_KEY_ID   encryption key id          (default "enc-2026q1")
//!
//! NOTE: this is a test/demo client, it logs real events on the target server.

use std::io::{Read, Write};
use std::net::TcpStream;

use sesame::canonical::{body_hash_hex, request_canonical};
use sesame::keys::{AeadKey, ChannelScope, HmacKey, StaticKeyProvider};
use sesame::message::{hex_decode, hex_encode, SesameHeaders, PROTOCOL_VERSION};
use sesame::replay::InMemoryReplayCache;
use sesame::tier1_hmac::sign;
use sesame::tier3_aead::{aad_for_headers, random_iv, seal, KEY_LEN};
use sesame::{verify_request, RequestContext, SesameConfig, Tier};
use time::OffsetDateTime;

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// RFC3339 (UTC, second precision) without pulling time's `formatting` feature.
fn rfc3339(dt: OffsetDateTime) -> String {
    let (y, m, d) = dt.to_calendar_date();
    let (h, mi, s) = dt.to_hms();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        u8::from(m),
        d,
        h,
        mi,
        s
    )
}

/// Extract a flat `"name":"value"` string field, trying each candidate name.
fn json_field(src: &str, names: &[&str]) -> Option<String> {
    for n in names {
        let needle = format!("\"{n}\"");
        if let Some(i) = src.find(&needle) {
            let rest = &src[i + needle.len()..];
            let colon = rest.find(':')?;
            let after = &rest[colon + 1..];
            let q1 = after.find('"')? + 1;
            let q2 = after[q1..].find('"')? + q1;
            return Some(after[q1..q2].to_string());
        }
    }
    None
}

fn esam_xml(sig_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><SignalProcessingEvent xmlns=\"urn:cablelabs:iptvservices:esam:xsd:signal:1\">\
<AcquiredSignal acquisitionSignalID=\"{sig_id}\"><UTCPoint utcPoint=\"2026-06-02T05:00:00Z\"/>\
<BinaryData signalType=\"SCTE35\">/DAWAAAAAAAAAP/wBQb+AAAAAAAAf+sBeA==</BinaryData></AcquiredSignal></SignalProcessingEvent>"
    )
}

/// Minimal dependency-free HTTP/1.1 POST. Returns (status_code, raw_response_text).
fn http_post(
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<(u16, String)> {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = hostport.split(':').next().unwrap_or(hostport);
    let mut stream = TcpStream::connect(hostport)?;
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    stream.write_all(body)?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    let text = String::from_utf8_lossy(&resp).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((status, text))
}

fn main() {
    let keys_path = env("SESAME_KEYS", "");
    if keys_path.is_empty() {
        eprintln!("set SESAME_KEYS=<path to keys.json> (see the file header for the schema)");
        std::process::exit(1);
    }
    let src = std::fs::read_to_string(&keys_path).expect("read keys file");
    let signing_hex =
        json_field(&src, &["signing_secret_hex", "sas_secret_hex"]).expect("signing key hex field");
    let enc_hex =
        json_field(&src, &["enc_key_hex", "encryption_key_hex"]).expect("encryption key hex field");

    let signing = hex_decode(&signing_hex).expect("signing key hex decode");
    let enc_vec = hex_decode(&enc_hex).expect("enc key hex decode");
    assert_eq!(
        enc_vec.len(),
        KEY_LEN,
        "encryption key must be {KEY_LEN} bytes"
    );
    let mut enc_key = [0u8; KEY_LEN];
    enc_key.copy_from_slice(&enc_vec);

    let key_id = env("SESAME_KEY_ID", "sas-east-01");
    let enc_key_id = env("SESAME_ENC_KEY_ID", "enc-2026q1");
    let base = env("SESAME_URL", "http://127.0.0.1:3090");
    let channel = env("SESAME_CHANNEL", "default");

    // A provider mirroring a server, used only for the in-process self-check.
    let provider = StaticKeyProvider::new()
        .with_signing_key(&key_id, HmacKey(signing.clone()), ChannelScope::all())
        .with_aead_key(&enc_key_id, AeadKey(enc_key));
    let cfg = SesameConfig::default();

    for tier in [1u8, 2, 3] {
        let path = format!("/esam?channel={channel}");
        let url = format!("{base}{path}");
        let ts = rfc3339(OffsetDateTime::now_utc());
        let iv = random_iv();
        let nonce = format!("ex-{tier}-{}", hex_encode(&iv)); // unique per request
        let plaintext = esam_xml(&format!("sesame-example-T{tier}"));
        // Tier 2+ declares a channel scope (bound into the signature and AAD).
        let scope = if tier >= 2 {
            Some(format!("channel={channel}"))
        } else {
            None
        };

        // Tier 3: AEAD-seal the body; the wire body is ciphertext (encrypt-then-MAC).
        let (wire, encrypted, iv_hex): (Vec<u8>, bool, Option<String>) = if tier == 3 {
            let aad = aad_for_headers(PROTOCOL_VERSION, &key_id, &ts, &nonce, scope.as_deref());
            let ct = seal(&enc_key, &iv, &aad, plaintext.as_bytes()).expect("seal");
            (ct, true, Some(hex_encode(&iv)))
        } else {
            (plaintext.into_bytes(), false, None)
        };

        // Sign the canonical over the body AS TRANSMITTED.
        let body_hash = body_hash_hex(&wire);
        let canonical = request_canonical("POST", &path, &ts, &nonce, &body_hash, scope.as_deref());
        let signature = sign(&signing, &canonical);

        let headers = SesameHeaders {
            version: Some(PROTOCOL_VERSION.to_string()),
            key_id: Some(key_id.clone()),
            timestamp: Some(ts.clone()),
            nonce: Some(nonce.clone()),
            signature: Some(signature.clone()),
            scope: scope.clone(),
            encrypted,
            enc_key_id: if tier == 3 {
                Some(enc_key_id.clone())
            } else {
                None
            },
            iv: iv_hex.clone(),
        };

        // ---- Self-check against the verifier before sending ----
        let replay = InMemoryReplayCache::new(cfg.replay_window_secs);
        let ctx = RequestContext {
            method: "POST",
            path: &path,
            target_channel: None,
        };
        match verify_request(
            &cfg,
            &provider,
            &replay,
            &ctx,
            &headers,
            &wire,
            OffsetDateTime::now_utc(),
            Tier::Zero,
        ) {
            Ok(v) if v.achieved_tier == Tier::from_u8(tier) => {
                println!("[T{tier}] self-check OK (achieved {:?})", v.achieved_tier)
            }
            Ok(v) => {
                eprintln!("[T{tier}] self-check tier mismatch: {:?}", v.achieved_tier);
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("[T{tier}] self-check FAILED: {e:?} (construction is wrong)");
                std::process::exit(2);
            }
        }

        // ---- Send over HTTP ----
        let mut hdrs = vec![
            (
                "Content-Type".to_string(),
                if tier == 3 {
                    "application/octet-stream"
                } else {
                    "application/xml"
                }
                .to_string(),
            ),
            ("X-SESAME-Version".to_string(), PROTOCOL_VERSION.to_string()),
            ("X-SESAME-KeyId".to_string(), key_id.clone()),
            ("X-SESAME-Timestamp".to_string(), ts.clone()),
            ("X-SESAME-Nonce".to_string(), nonce.clone()),
            ("X-SESAME-Signature".to_string(), signature.clone()),
        ];
        if let Some(s) = &scope {
            hdrs.push(("X-SESAME-Scope".to_string(), s.clone()));
        }
        if tier == 3 {
            hdrs.push(("X-SESAME-Encrypted".to_string(), "true".to_string()));
            hdrs.push(("X-SESAME-EncKeyId".to_string(), enc_key_id.clone()));
            hdrs.push(("X-SESAME-IV".to_string(), iv_hex.clone().unwrap()));
        }
        match http_post(&url, &hdrs, &wire) {
            Ok((status, text)) => {
                let lower = text.to_ascii_lowercase();
                let signed = lower.contains("x-sesame-signature");
                let resp_enc = lower.contains("x-sesame-encrypted: true");
                println!(
                    "[T{tier}] -> {channel}: HTTP {status}  response_signed={signed} response_encrypted={resp_enc}"
                );
            }
            Err(e) => eprintln!("[T{tier}] send error: {e}"),
        }
    }
}
