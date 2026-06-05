//! Tier 3, AES-256-GCM payload encryption.
//!
//! The body is encrypted before it is signed, so the tier 1 signature covers
//! the ciphertext (see [`crate::canonical`]). GCM's own authentication tag
//! additionally binds a small associated-data string built from the
//! already-authenticated headers, so the two layers reinforce rather than
//! duplicate each other.
//!
//! The IV is caller-supplied (12 bytes, unique per key+message): the core takes
//! no RNG dependency. AES-GCM appends its 16-byte tag to the ciphertext; we
//! split it out so it can travel in `X-Sesame-Tag` while the ciphertext travels
//! as the body.

use crate::error::SesameError;
use crate::types::{ChannelScope, KeyId, Nonce, UnixTime};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};

/// Length of the GCM authentication tag, in bytes.
pub const TAG_LEN: usize = 16;
/// Required AES-256 key length, in bytes.
pub const KEY_LEN: usize = 32;
/// Required GCM IV length, in bytes.
pub const IV_LEN: usize = 12;

/// Associated data bound by GCM. Built from fields that are *also* covered by
/// the tier 1 signature, so encryption is bound to the same request context
/// without the circular dependency of feeding the whole signing string (which
/// itself hashes the ciphertext) into the cipher.
pub fn associated_data(
    key_id: &KeyId,
    ts: UnixTime,
    nonce: &Nonce,
    channel: Option<&ChannelScope>,
) -> Vec<u8> {
    let chan = channel.map(|c| c.0.as_str()).unwrap_or("");
    format!(
        "SESAME-AAD\n{}\n{}\n{}\n{}",
        key_id.0,
        ts.as_secs(),
        crate::encoding::b64_encode(nonce.as_bytes()),
        chan,
    )
    .into_bytes()
}

/// Encrypt `plaintext`, returning `(ciphertext, tag)`.
///
/// `key` must be exactly [`KEY_LEN`] bytes; otherwise [`SesameError::Encryption`].
pub fn encrypt(
    key: &[u8],
    iv: &[u8; IV_LEN],
    key_id: &KeyId,
    ts: UnixTime,
    nonce: &Nonce,
    channel: Option<&ChannelScope>,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), SesameError> {
    if key.len() != KEY_LEN {
        return Err(SesameError::Encryption);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SesameError::Encryption)?;
    let aad = associated_data(key_id, ts, nonce, channel);
    let mut out = cipher
        .encrypt(
            GcmNonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SesameError::Encryption)?;
    // RustCrypto appends the tag; peel it off.
    let split = out.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out[split..]);
    out.truncate(split);
    Ok((out, tag))
}

/// Decrypt `ciphertext` (tag separate), returning the plaintext.
///
/// Returns [`SesameError::Decryption`] on any authentication failure, wrong
/// key, tampered ciphertext, mismatched AAD, or wrong tag. The error carries no
/// detail by design.
#[allow(clippy::too_many_arguments)]
pub fn decrypt(
    key: &[u8],
    iv: &[u8; IV_LEN],
    tag: &[u8; TAG_LEN],
    key_id: &KeyId,
    ts: UnixTime,
    nonce: &Nonce,
    channel: Option<&ChannelScope>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SesameError> {
    if key.len() != KEY_LEN {
        return Err(SesameError::Decryption);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SesameError::Decryption)?;
    let aad = associated_data(key_id, ts, nonce, channel);
    let mut combined = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    cipher
        .decrypt(
            GcmNonce::from_slice(iv),
            Payload {
                msg: &combined,
                aad: &aad,
            },
        )
        .map_err(|_| SesameError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> (Vec<u8>, [u8; IV_LEN], KeyId, UnixTime, Nonce) {
        (
            vec![7u8; KEY_LEN],
            [3u8; IV_LEN],
            KeyId("k".into()),
            UnixTime(42),
            Nonce(vec![1u8; 16]),
        )
    }

    #[test]
    fn round_trips() {
        let (key, iv, kid, ts, nonce) = ctx();
        let (ct, tag) = encrypt(&key, &iv, &kid, ts, &nonce, None, b"hello").unwrap();
        assert_ne!(ct, b"hello");
        let pt = decrypt(&key, &iv, &tag, &kid, ts, &nonce, None, &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (key, iv, kid, ts, nonce) = ctx();
        let (mut ct, tag) = encrypt(&key, &iv, &kid, ts, &nonce, None, b"hello").unwrap();
        ct[0] ^= 0xff;
        assert_eq!(
            decrypt(&key, &iv, &tag, &kid, ts, &nonce, None, &ct),
            Err(SesameError::Decryption)
        );
    }

    #[test]
    fn mismatched_aad_fails() {
        let (key, iv, kid, ts, nonce) = ctx();
        let (ct, tag) = encrypt(&key, &iv, &kid, ts, &nonce, None, b"hello").unwrap();
        // Decrypt claiming a different channel → AAD differs → auth fails.
        let other = ChannelScope("other".into());
        assert_eq!(
            decrypt(&key, &iv, &tag, &kid, ts, &nonce, Some(&other), &ct),
            Err(SesameError::Decryption)
        );
    }

    #[test]
    fn wrong_key_length_rejected() {
        assert_eq!(
            encrypt(
                &[0u8; 16],
                &[0u8; IV_LEN],
                &KeyId("k".into()),
                UnixTime(1),
                &Nonce(vec![0; 16]),
                None,
                b"x"
            ),
            Err(SesameError::Encryption)
        );
    }
}
