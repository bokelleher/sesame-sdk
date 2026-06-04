//! Tier 1 — HMAC-SHA256 authentication and integrity — plus the freshness rule.
//!
//! [`sign`] and [`verify_signature`] are pure and synchronous: no clock, no
//! RNG, no I/O. The caller supplies the timestamp and nonce (and, for tier 3,
//! the IV), which is what makes the conformance vectors deterministic.
//!
//! Freshness ([`check_freshness`]) is a *separate* function, invoked by the host
//! after the signature verifies and before/with the replay check (handoff §5).
//! The core owns the rule; the host owns the clock and the replay memory.

use crate::canonical::Canonical;
use crate::cipher;
use crate::encoding::{b64_decode, b64_encode};
use crate::error::SesameError;
use crate::headers::HeaderSource;
use crate::types::{
    header, ChannelScope, EncryptionInfo, EncryptionParams, Key, KeyId, Nonce, RequestParts,
    Signed, UnixTime, Verified, ENC_AES_256_GCM, VERSION,
};
use core::time::Duration;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over `data`. HMAC accepts a key of any length, so this
/// never fails.
fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Sign a request, producing the SESAME headers and the body to transmit.
///
/// `plaintext_body` is the application payload. Without `encryption` it is
/// echoed back as the transmitted body; with `encryption` (tier 3) it is
/// AES-256-GCM-encrypted first and the ciphertext is what gets signed and sent.
pub fn sign(
    parts: &RequestParts,
    key: &Key,
    nonce: &Nonce,
    timestamp: UnixTime,
    plaintext_body: &[u8],
    encryption: Option<EncryptionParams>,
) -> Result<Signed, SesameError> {
    let mut headers: Vec<(&'static str, String)> = Vec::with_capacity(9);
    headers.push((header::VERSION, VERSION.to_string()));
    headers.push((header::KEY_ID, parts.key_id.0.clone()));
    headers.push((header::TIMESTAMP, timestamp.as_secs().to_string()));
    headers.push((header::NONCE, b64_encode(nonce.as_bytes())));
    if let Some(ch) = &parts.channel {
        headers.push((header::CHANNEL, ch.0.clone()));
    }

    // Tier 3: encrypt first so the signature covers the ciphertext.
    let transmit_body = match encryption {
        Some(params) => {
            let (ciphertext, tag) = cipher::encrypt(
                key.as_bytes(),
                &params.iv,
                &parts.key_id,
                timestamp,
                nonce,
                parts.channel.as_ref(),
                plaintext_body,
            )?;
            headers.push((header::ENCRYPTION, ENC_AES_256_GCM.to_string()));
            headers.push((header::IV, b64_encode(&params.iv)));
            headers.push((header::TAG, b64_encode(&tag)));
            ciphertext
        }
        None => plaintext_body.to_vec(),
    };

    let signing_string = Canonical {
        version: VERSION,
        method: parts.method,
        target: parts.target,
        key_id: &parts.key_id,
        timestamp,
        nonce,
        channel: parts.channel.as_ref(),
        body: &transmit_body,
    }
    .to_signing_string();

    let signature = mac(key.as_bytes(), signing_string.as_bytes());
    headers.push((header::SIGNATURE, b64_encode(&signature)));

    Ok(Signed {
        headers,
        body: transmit_body,
    })
}

/// Verify the tier 1 signature (and parse tier 2/3 metadata) for a received
/// request. On success the returned [`Verified`] facts are authentic.
///
/// This does **not** check freshness or replay — call [`check_freshness`] and
/// the host's [`NonceStore`](crate::traits::NonceStore) next. `method` and
/// `target` are the request line, supplied by the host (they are not SESAME
/// headers but they are bound by the signature).
pub fn verify_signature(
    method: &str,
    target: &str,
    headers: &impl HeaderSource,
    body: &[u8],
    key: &Key,
) -> Result<Verified, SesameError> {
    let get = |name: &'static str| headers.get(name).ok_or(SesameError::MissingHeader(name));

    let version = get(header::VERSION)?;
    if version != VERSION {
        return Err(SesameError::UnsupportedVersion(version.to_string()));
    }
    let key_id = KeyId(get(header::KEY_ID)?.to_string());

    let timestamp = {
        let raw = get(header::TIMESTAMP)?;
        UnixTime(
            raw.parse::<u64>()
                .map_err(|_| SesameError::MalformedHeader {
                    header: header::TIMESTAMP,
                    reason: "not a non-negative integer",
                })?,
        )
    };

    let nonce = Nonce(b64_decode(header::NONCE, get(header::NONCE)?)?);
    let channel = headers
        .get(header::CHANNEL)
        .map(|c| ChannelScope(c.to_string()));

    // Tier 3 metadata, if present.
    let encryption = match headers.get(header::ENCRYPTION) {
        None => None,
        Some(suite) => {
            if suite != ENC_AES_256_GCM {
                return Err(SesameError::UnsupportedEncryption(suite.to_string()));
            }
            let iv_bytes = b64_decode(header::IV, get(header::IV)?)?;
            let tag_bytes = b64_decode(header::TAG, get(header::TAG)?)?;
            let iv: [u8; cipher::IV_LEN] =
                iv_bytes
                    .try_into()
                    .map_err(|_| SesameError::MalformedHeader {
                        header: header::IV,
                        reason: "expected 12 bytes",
                    })?;
            let tag: [u8; cipher::TAG_LEN] =
                tag_bytes
                    .try_into()
                    .map_err(|_| SesameError::MalformedHeader {
                        header: header::TAG,
                        reason: "expected 16 bytes",
                    })?;
            Some(EncryptionInfo {
                suite: suite.to_string(),
                iv,
                tag,
            })
        }
    };

    let signature = b64_decode(header::SIGNATURE, get(header::SIGNATURE)?)?;

    let signing_string = Canonical {
        version,
        method,
        target,
        key_id: &key_id,
        timestamp,
        nonce: &nonce,
        channel: channel.as_ref(),
        body,
    }
    .to_signing_string();

    // Constant-time verify; also rejects wrong-length signatures.
    let mut m = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    m.update(signing_string.as_bytes());
    m.verify_slice(&signature)
        .map_err(|_| SesameError::SignatureMismatch)?;

    Ok(Verified {
        key_id,
        timestamp,
        nonce,
        channel,
        encryption,
    })
}

/// Decrypt a tier 3 body using the metadata recovered during verification.
///
/// Returns [`SesameError::Decryption`] if `verified` carried no encryption info
/// (i.e. the request was not tier 3) or if GCM authentication fails.
pub fn decrypt_body(
    verified: &Verified,
    key: &Key,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SesameError> {
    let info = verified
        .encryption
        .as_ref()
        .ok_or(SesameError::Decryption)?;
    cipher::decrypt(
        key.as_bytes(),
        &info.iv,
        &info.tag,
        &verified.key_id,
        verified.timestamp,
        &verified.nonce,
        verified.channel.as_ref(),
        ciphertext,
    )
}

/// The freshness rule: reject if the request's clock skew exceeds `±window`.
///
/// `skew = now - timestamp`. Future-dated requests (negative skew) are rejected
/// symmetrically, which bounds how long a stolen-but-future-dated request can
/// loiter before its nonce can be evicted.
pub fn check_freshness(
    timestamp: UnixTime,
    now: UnixTime,
    window: Duration,
) -> Result<(), SesameError> {
    let skew = now.as_secs() as i64 - timestamp.as_secs() as i64;
    if skew.unsigned_abs() > window.as_secs() {
        return Err(SesameError::Stale {
            skew_secs: skew,
            window_secs: window.as_secs(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key(b"a-shared-secret-key".to_vec())
    }

    fn parts() -> RequestParts<'static> {
        RequestParts {
            method: "POST",
            target: "/esam/signal",
            key_id: KeyId("encoder-7".into()),
            channel: Some(ChannelScope("wxyz-hd".into())),
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let signed = sign(
            &parts(),
            &key(),
            &Nonce(vec![9u8; 16]),
            UnixTime(1000),
            b"<spn/>",
            None,
        )
        .unwrap();
        let v = verify_signature(
            "POST",
            "/esam/signal",
            &signed.headers,
            &signed.body,
            &key(),
        )
        .unwrap();
        assert_eq!(v.key_id, KeyId("encoder-7".into()));
        assert_eq!(v.channel, Some(ChannelScope("wxyz-hd".into())));
        assert!(v.encryption.is_none());
    }

    #[test]
    fn tampered_body_fails_verification() {
        let signed = sign(
            &parts(),
            &key(),
            &Nonce(vec![9u8; 16]),
            UnixTime(1000),
            b"<spn/>",
            None,
        )
        .unwrap();
        let bad = b"<spn>tampered</spn>";
        assert_eq!(
            verify_signature("POST", "/esam/signal", &signed.headers, bad, &key()),
            Err(SesameError::SignatureMismatch)
        );
    }

    #[test]
    fn different_target_fails_verification() {
        let signed = sign(
            &parts(),
            &key(),
            &Nonce(vec![9u8; 16]),
            UnixTime(1000),
            b"<spn/>",
            None,
        )
        .unwrap();
        assert_eq!(
            verify_signature("POST", "/esam/other", &signed.headers, &signed.body, &key()),
            Err(SesameError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signed = sign(
            &parts(),
            &key(),
            &Nonce(vec![9u8; 16]),
            UnixTime(1000),
            b"<spn/>",
            None,
        )
        .unwrap();
        let other = Key(b"different-secret".to_vec());
        assert_eq!(
            verify_signature(
                "POST",
                "/esam/signal",
                &signed.headers,
                &signed.body,
                &other
            ),
            Err(SesameError::SignatureMismatch)
        );
    }

    #[test]
    fn freshness_window() {
        let window = Duration::from_secs(300);
        assert!(check_freshness(UnixTime(1000), UnixTime(1200), window).is_ok());
        assert!(check_freshness(UnixTime(1000), UnixTime(800), window).is_ok());
        assert!(matches!(
            check_freshness(UnixTime(1000), UnixTime(1400), window),
            Err(SesameError::Stale { .. })
        ));
        // Future-dated beyond the window is rejected too.
        assert!(matches!(
            check_freshness(UnixTime(1000), UnixTime(600), window),
            Err(SesameError::Stale {
                skew_secs: -400,
                ..
            })
        ));
    }
}
