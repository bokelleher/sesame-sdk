// src/sesame/tier3_aead.rs
//
// Tier 3, Payload encryption (AES-256-GCM). Spec: ANSI/SCTE 130-9 (SESAME)
// draft v0.5 §8.4.
//
// Parameters (paper §8.5 item 4, §4 of the handoff): AES-256-GCM, 96-bit IV,
// 128-bit tag. The GCM tag is appended to the ciphertext (`aes-gcm` crate
// convention), giving authenticated encryption. Output body = ciphertext||tag.
//
// [BO-5] AAD is not specified by the paper (§8.4 omits it entirely). Decision:
// AAD = the canonical SESAME header set bytes, binding the ciphertext to
// version/key-id/timestamp/nonce/scope so headers cannot be swapped under the
// encryption. The exact byte layout is produced by `aad_for_headers`. Drop-in
// paper fix: docs/SESAME_paper_errata.md E2 (adds AAD to §8.4 / §8.5 item 11).
//
// [BO-4] IV uniqueness: Appendix A.4 reuses the same IV on request and response
// under the same EncKeyId, a catastrophic GCM nonce reuse. This implementation
// ALWAYS draws a fresh IV from the OS CSPRNG per message (`random_iv`). Drop-in
// paper fix: docs/SESAME_paper_errata.md E1 (distinct response IV + normative
// IV-uniqueness SHALL). The code is already correct; the paper text is the bug.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::message::SesameError;

/// AES-256 key size in bytes.
pub const KEY_LEN: usize = 32;
/// GCM IV/nonce size in bytes (96 bits, §8.5).
pub const IV_LEN: usize = 12;

/// Draw a fresh 96-bit GCM IV from the OS CSPRNG. MUST be called once per
/// message; never reuse an IV with the same key (NIST SP 800-38D).
///
/// Behind the default-on `rng` feature: verify-only/embedded hosts that supply
/// their own IVs can build without an RNG dependency.
#[cfg(feature = "rng")]
pub fn random_iv() -> [u8; IV_LEN] {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    iv
}

/// Encrypt `plaintext` with AES-256-GCM. Returns `ciphertext || tag`.
pub fn seal(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SesameError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SesameError::DecryptFailed)
}

/// Decrypt `ciphertext` (which includes the appended GCM tag) with AES-256-GCM.
/// Returns the plaintext, or `DecryptFailed` if the tag does not verify under
/// the key, IV and AAD (`sesame_decrypt_failed`, Appendix A.7).
pub fn open(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SesameError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SesameError::DecryptFailed)
}

/// Canonical AAD byte layout ([BO], see header). Newline-joined SESAME header
/// set: version, key-id, timestamp, nonce, and (if Tier 2) the scope value.
pub fn aad_for_headers(
    version: &str,
    key_id: &str,
    timestamp: &str,
    nonce: &str,
    scope: Option<&str>,
) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(version);
    s.push('\n');
    s.push_str(key_id);
    s.push('\n');
    s.push_str(timestamp);
    s.push('\n');
    s.push_str(nonce);
    if let Some(scope) = scope {
        s.push('\n');
        s.push_str(scope);
    }
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::hex_decode;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; KEY_LEN];
        let iv = random_iv();
        let aad = b"aad";
        let pt = b"<SignalProcessingEvent/>";
        let ct = seal(&key, &iv, aad, pt).unwrap();
        assert_ne!(&ct[..], &pt[..]); // encrypted
        assert_eq!(ct.len(), pt.len() + 16); // + 128-bit tag
        assert_eq!(open(&key, &iv, aad, &ct).unwrap(), pt);
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = [1u8; KEY_LEN];
        let iv = random_iv();
        let mut ct = seal(&key, &iv, b"", b"hello").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a tag bit
        assert_eq!(open(&key, &iv, b"", &ct), Err(SesameError::DecryptFailed));
    }

    #[test]
    fn wrong_aad_rejected() {
        let key = [2u8; KEY_LEN];
        let iv = random_iv();
        let ct = seal(&key, &iv, b"headers-A", b"x").unwrap();
        assert_eq!(
            open(&key, &iv, b"headers-B", &ct),
            Err(SesameError::DecryptFailed)
        );
    }

    #[test]
    fn fresh_iv_each_call() {
        assert_ne!(random_iv(), random_iv());
    }

    #[test]
    fn nist_gcm_known_answer() {
        // NIST SP 800-38D / Gladman AES-256-GCM test vector (Test Case 16):
        // K  = feffe9928665731c6d6a8f9467308308 feffe9928665731c6d6a8f9467308308
        // IV = cafebabefacedbaddecaf888
        // P  = d9313225f88406e5a55909c5aff5269a 86a7a9531534f7da2e4c303d8a318a72
        //      1c3c0c95956809532fcf0e2449a6b525 b16aedf5aa0de657ba637b39
        // A  = feedfacedeadbeeffeedfacedeadbeef abaddad2
        // C  = 522dc1f099567d07f47f37a32a84427d 643a8cdcbfe5c0c97598a2bd2555d1aa
        //      8cb08e48590dbb3da7b08b1056828838 c5f61e6393ba7a0abcc9f662
        // T  = 76fc6ece0f4e1768cddf8853bb2d551b
        let key =
            hex_decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308").unwrap();
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&key);
        let iv = hex_decode("cafebabefacedbaddecaf888").unwrap();
        let mut nonce = [0u8; IV_LEN];
        nonce.copy_from_slice(&iv);
        let pt = hex_decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let aad = hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected = hex_decode(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
             76fc6ece0f4e1768cddf8853bb2d551b",
        )
        .unwrap();
        let ct = seal(&k, &nonce, &aad, &pt).unwrap();
        assert_eq!(
            ct, expected,
            "AES-256-GCM ciphertext||tag must match NIST vector"
        );
    }
}
