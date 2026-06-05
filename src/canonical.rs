//! The canonical signing string, the one byte-exact artifact that signer and
//! verifier MUST agree on, or they do not interoperate at all (handoff §2).
//!
//! ## Format (v1, PROVISIONAL)
//!
//! The string is exactly these nine fields, each on its own line, joined by a
//! single LF (`0x0A`). There is **no trailing newline**.
//!
//! ```text
//! SESAME-HMAC-SHA256
//! <version>
//! <method, uppercased>
//! <request-target>            (path plus optional "?query", exactly as sent)
//! <key-id>
//! <timestamp, decimal seconds>
//! <nonce, base64>
//! <channel scope, or empty line if tier 2 unused>
//! <lowercase hex SHA-256 of the transmitted body bytes>
//! ```
//!
//! The HMAC-SHA256 is computed over the UTF-8 bytes of this string.
//!
//! Under tier 3 the "transmitted body" is the ciphertext, so the body hash
//! binds the signature to the encrypted bytes actually on the wire.
//!
//! > **PROVISIONAL, reconcile before first interop.** This layout is the
//! > scaffold's proposal, *not* yet confirmed against the deployed rust-pois
//! > implementation. Per handoff §3 the real extraction MOVES the deployed
//! > canonicalization byte-for-byte; if it differs (field order, separators,
//! > timestamp granularity, target normalization), this module and the
//! > conformance vectors change to match the deployment, and rust-pois becomes
//! > the source of truth. Do not treat these vectors as a published standard
//! > until that reconciliation happens.

use crate::encoding::b64_encode;
use crate::encoding::hex_encode;
use crate::types::{ChannelScope, KeyId, Nonce, UnixTime};
use sha2::{Digest, Sha256};

/// The fixed first line: algorithm tag plus an implicit binding to HMAC-SHA256.
pub const ALG_TAG: &str = "SESAME-HMAC-SHA256";

/// Inputs to the canonical string. Borrowed so building is allocation-light.
#[derive(Debug)]
pub struct Canonical<'a> {
    pub version: &'a str,
    pub method: &'a str,
    pub target: &'a str,
    pub key_id: &'a KeyId,
    pub timestamp: UnixTime,
    pub nonce: &'a Nonce,
    pub channel: Option<&'a ChannelScope>,
    /// The bytes as transmitted (ciphertext under tier 3).
    pub body: &'a [u8],
}

impl Canonical<'_> {
    /// Render the canonical signing string.
    pub fn to_signing_string(&self) -> String {
        let body_hash = hex_encode(Sha256::digest(self.body).as_slice());
        let channel = self.channel.map(|c| c.0.as_str()).unwrap_or("");
        // Nine LF-joined fields, no trailing newline.
        [
            ALG_TAG,
            self.version,
            &self.method.to_ascii_uppercase(),
            self.target,
            self.key_id.0.as_str(),
            &self.timestamp.as_secs().to_string(),
            &b64_encode(self.nonce.as_bytes()),
            channel,
            &body_hash,
        ]
        .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (KeyId, Nonce) {
        (KeyId("key-1".into()), Nonce(vec![0u8; 16]))
    }

    #[test]
    fn nine_lines_no_trailing_newline() {
        let (key_id, nonce) = sample();
        let s = Canonical {
            version: "1",
            method: "post",
            target: "/esam/signal",
            key_id: &key_id,
            timestamp: UnixTime(1_700_000_000),
            nonce: &nonce,
            channel: Some(&ChannelScope("wxyz-hd".into())),
            body: b"<SignalProcessingNotification/>",
        }
        .to_signing_string();

        let lines: Vec<&str> = s.split('\n').collect();
        assert_eq!(lines.len(), 9);
        assert!(!s.ends_with('\n'));
        assert_eq!(lines[0], "SESAME-HMAC-SHA256");
        assert_eq!(lines[2], "POST", "method is uppercased");
        assert_eq!(lines[7], "wxyz-hd");
    }

    #[test]
    fn absent_channel_is_an_empty_line() {
        let (key_id, nonce) = sample();
        let s = Canonical {
            version: "1",
            method: "POST",
            target: "/x",
            key_id: &key_id,
            timestamp: UnixTime(1),
            nonce: &nonce,
            channel: None,
            body: b"",
        }
        .to_signing_string();
        let lines: Vec<&str> = s.split('\n').collect();
        assert_eq!(lines[7], "", "tier-2-absent leaves an empty channel line");
    }
}
