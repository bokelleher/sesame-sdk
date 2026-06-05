//! Generate the language-neutral conformance vectors (`test-vectors/*.json`).
//!
//! Run with: `cargo run --features cli --bin sesame-gen-vectors -- --out test-vectors`
//!
//! The vectors are derived from this crate's reference implementation. They are
//! the published cross-language contract; `tests/conformance.rs` re-derives them
//! from the current code and asserts a byte-for-byte match, so the committed
//! files can never silently drift from the implementation.

use std::path::PathBuf;

use clap::Parser;
use sesame::canonical::Canonical;
use sesame::cipher;
use sesame::encoding::{b64_encode, hex_decode, hex_encode};
use sesame::types::{ChannelScope, Key, KeyId, Nonce, RequestParts, UnixTime};
use sesame::vectors::{GcmVector, GcmVectorFile, SigningVector, SigningVectorFile};

#[derive(Parser)]
#[command(about = "Generate SESAME conformance test vectors")]
struct Args {
    /// Output directory for the JSON vector files.
    #[arg(long, default_value = "test-vectors")]
    out: PathBuf,
}

const PROVISIONAL_NOTE: &str =
    "PROVISIONAL, generated from the sesame reference impl; the canonical \
     signing-string layout must be reconciled against deployed rust-pois before \
     this is treated as a published standard (handoff §3).";

#[allow(clippy::too_many_arguments)]
fn signing_vector(
    description: &str,
    method: &str,
    target: &str,
    key_id: &str,
    key: &[u8],
    timestamp: u64,
    nonce: &[u8],
    channel: Option<&str>,
    body: &str,
) -> SigningVector {
    let key_id_t = KeyId(key_id.to_string());
    let nonce_t = Nonce(nonce.to_vec());
    let channel_t = channel.map(|c| ChannelScope(c.to_string()));
    let key_t = Key(key.to_vec());

    let signing_string = Canonical {
        version: sesame::VERSION,
        method,
        target,
        key_id: &key_id_t,
        timestamp: UnixTime(timestamp),
        nonce: &nonce_t,
        channel: channel_t.as_ref(),
        body: body.as_bytes(),
    }
    .to_signing_string();

    let parts = RequestParts {
        method,
        target,
        key_id: key_id_t,
        channel: channel_t,
    };
    let signed = sesame::sign(
        &parts,
        &key_t,
        &nonce_t,
        UnixTime(timestamp),
        body.as_bytes(),
        None,
    )
    .expect("sign");
    let signature = signed
        .header(sesame::header::SIGNATURE)
        .expect("signature header")
        .to_string();

    SigningVector {
        description: description.to_string(),
        version: sesame::VERSION.to_string(),
        method: method.to_string(),
        target: target.to_string(),
        key_id: key_id.to_string(),
        key_hex: hex_encode(key),
        timestamp,
        nonce_hex: hex_encode(nonce),
        channel: channel.map(str::to_string),
        body_utf8: body.to_string(),
        expected_signing_string: signing_string,
        expected_signature_b64: signature,
    }
}

#[allow(clippy::too_many_arguments)]
fn gcm_vector(
    description: &str,
    key: &[u8],
    iv: &[u8; 12],
    key_id: &str,
    timestamp: u64,
    nonce: &[u8],
    channel: Option<&str>,
    plaintext: &str,
) -> GcmVector {
    let key_id_t = KeyId(key_id.to_string());
    let nonce_t = Nonce(nonce.to_vec());
    let channel_t = channel.map(|c| ChannelScope(c.to_string()));

    let (ciphertext, tag) = cipher::encrypt(
        key,
        iv,
        &key_id_t,
        UnixTime(timestamp),
        &nonce_t,
        channel_t.as_ref(),
        plaintext.as_bytes(),
    )
    .expect("encrypt");

    let aad = cipher::associated_data(&key_id_t, UnixTime(timestamp), &nonce_t, channel_t.as_ref());

    GcmVector {
        description: description.to_string(),
        key_hex: hex_encode(key),
        iv_hex: hex_encode(iv),
        key_id: key_id.to_string(),
        timestamp,
        nonce_hex: hex_encode(nonce),
        channel: channel.map(str::to_string),
        plaintext_utf8: plaintext.to_string(),
        aad_utf8: String::from_utf8(aad).expect("aad is utf-8"),
        expected_ciphertext_hex: hex_encode(&ciphertext),
        expected_tag_b64: b64_encode(&tag),
    }
}

fn main() {
    let args = Args::parse();

    let hmac_key = hex_decode("a1b2c3d4e5f60718293a4b5c6d7e8f90").expect("key hex");
    let nonce16 = hex_decode("00112233445566778899aabbccddeeff").expect("nonce hex");

    let signing = SigningVectorFile {
        note: PROVISIONAL_NOTE.to_string(),
        vectors: vec![
            signing_vector(
                "tier1, no channel, empty body",
                "POST",
                "/esam/signal",
                "encoder-7",
                &hmac_key,
                1_700_000_000,
                &nonce16,
                None,
                "",
            ),
            signing_vector(
                "tier1+tier2, channel scope, xml body",
                "POST",
                "/esam/signal?ack=1",
                "encoder-7",
                &hmac_key,
                1_700_000_000,
                &nonce16,
                Some("wxyz-hd"),
                "<SignalProcessingNotification acquisitionPointIdentity=\"ap-1\"/>",
            ),
            signing_vector(
                "tier1, method lowercased on input is uppercased in canonical",
                "get",
                "/esam/status",
                "decoder-3",
                &hmac_key,
                1_699_999_999,
                &nonce16,
                Some("kxyz-sd"),
                "café ✓ π",
            ),
        ],
    };

    let aes_key = hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("aes key hex");
    let iv_bytes = hex_decode("a0a1a2a3a4a5a6a7a8a9aaab").expect("iv hex");
    let iv: [u8; 12] = iv_bytes.try_into().expect("iv is 12 bytes");

    let gcm = GcmVectorFile {
        note: PROVISIONAL_NOTE.to_string(),
        vectors: vec![
            gcm_vector(
                "tier3, no channel",
                &aes_key,
                &iv,
                "encoder-7",
                1_700_000_000,
                &nonce16,
                None,
                "top-secret avail payload",
            ),
            gcm_vector(
                "tier3, channel scope bound in AAD",
                &aes_key,
                &iv,
                "encoder-7",
                1_700_000_000,
                &nonce16,
                Some("wxyz-hd"),
                "top-secret avail payload",
            ),
            gcm_vector(
                "tier3, empty plaintext",
                &aes_key,
                &iv,
                "encoder-7",
                1_700_000_000,
                &nonce16,
                None,
                "",
            ),
        ],
    };

    std::fs::create_dir_all(&args.out).expect("create out dir");
    let signing_path = args.out.join("signing.json");
    let gcm_path = args.out.join("gcm.json");
    std::fs::write(
        &signing_path,
        serde_json::to_string_pretty(&signing).expect("serialize signing") + "\n",
    )
    .expect("write signing.json");
    std::fs::write(
        &gcm_path,
        serde_json::to_string_pretty(&gcm).expect("serialize gcm") + "\n",
    )
    .expect("write gcm.json");

    println!("wrote {}", signing_path.display());
    println!("wrote {}", gcm_path.display());
}
