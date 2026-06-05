// src/sesame/tier1_hmac.rs
//
// Tier 1, Authentication + Integrity (HMAC-SHA256) and timestamp freshness.
// Spec: ANSI/SCTE 130-9 (SESAME) draft v0.5 §8.2.
//
// Signatures are lowercase hex of HMAC-SHA256 over the canonical string
// (canonical.rs). Verification is constant-time via `Mac::verify_slice`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::message::{hex_decode, hex_encode, SesameError};

type HmacSha256 = Hmac<Sha256>;

/// Compute the lowercase-hex HMAC-SHA256 of `canonical` under `key`.
pub fn sign(key: &[u8], canonical: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// Constant-time verification of a provided lowercase-hex signature against
/// `canonical` under `key`. Returns `Ok(())` only on an exact match.
///
/// Uses `Mac::verify_slice`, which performs a constant-time tag comparison, so
/// the verification path leaks no timing information about how many leading
/// bytes matched (handoff §8 "no-leak").
pub fn verify(key: &[u8], canonical: &str, provided_hex: &str) -> Result<(), SesameError> {
    let provided = hex_decode(provided_hex).ok_or(SesameError::SignatureMismatch)?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    mac.verify_slice(&provided)
        .map_err(|_| SesameError::SignatureMismatch)
}

/// Verify against any one of several candidate keys (key-rotation overlap
/// window, §8.2.5). Succeeds if *any* key validates the signature. Each
/// candidate is checked in constant time; we do not early-out on a mismatch in
/// a way that reveals which key matched.
pub fn verify_any(
    keys: &[Vec<u8>],
    canonical: &str,
    provided_hex: &str,
) -> Result<(), SesameError> {
    let provided = match hex_decode(provided_hex) {
        Some(p) => p,
        None => return Err(SesameError::SignatureMismatch),
    };
    let mut ok = false;
    for key in keys {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(canonical.as_bytes());
        if mac.verify_slice(&provided).is_ok() {
            ok = true;
        }
    }
    if ok {
        Ok(())
    } else {
        Err(SesameError::SignatureMismatch)
    }
}

/// Validate that `timestamp_iso` (ISO-8601 / RFC 3339 UTC, e.g.
/// `2026-02-24T18:00:00Z`) is within `±window_secs` of `now` (§8.2.4; default
/// window 300 s per §8.5 item 6). Rejects unparseable or stale timestamps.
pub fn check_freshness(
    timestamp_iso: &str,
    now: OffsetDateTime,
    window_secs: i64,
) -> Result<(), SesameError> {
    let ts = OffsetDateTime::parse(timestamp_iso, &Rfc3339)
        .map_err(|_| SesameError::ExpiredTimestamp)?;
    let delta = now.unix_timestamp() - ts.unix_timestamp();
    if delta.abs() <= window_secs {
        Ok(())
    } else {
        Err(SesameError::ExpiredTimestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = b"shared-secret";
        let sig = sign(key, "canonical-string");
        assert_eq!(sig.len(), 64); // 32-byte HMAC as hex
        assert!(verify(key, "canonical-string", &sig).is_ok());
    }

    #[test]
    fn wrong_key_rejected() {
        let sig = sign(b"k1", "c");
        assert_eq!(
            verify(b"k2", "c", &sig),
            Err(SesameError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_canonical_rejected() {
        let key = b"k";
        let sig = sign(key, "original");
        assert_eq!(
            verify(key, "tampered", &sig),
            Err(SesameError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_any_accepts_old_or_new_key() {
        let old = b"old-key".to_vec();
        let new = b"new-key".to_vec();
        let sig_old = sign(&old, "c");
        assert!(verify_any(&[old.clone(), new.clone()], "c", &sig_old).is_ok());
        let sig_new = sign(&new, "c");
        assert!(verify_any(&[old, new], "c", &sig_new).is_ok());
    }

    #[test]
    fn rfc2104_known_answer() {
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        // Expected HMAC-SHA256 from the RFC.
        let sig = sign(b"Jefe", "what do ya want for nothing?");
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn freshness_window() {
        let now = OffsetDateTime::parse("2026-02-24T18:05:00Z", &Rfc3339).unwrap();
        // 300s earlier, on the edge, accepted.
        assert!(check_freshness("2026-02-24T18:00:00Z", now, 300).is_ok());
        // 301s earlier, rejected.
        assert_eq!(
            check_freshness("2026-02-24T17:59:59Z", now, 300),
            Err(SesameError::ExpiredTimestamp)
        );
        // Future skew beyond window, rejected.
        assert_eq!(
            check_freshness("2026-02-24T18:10:01Z", now, 300),
            Err(SesameError::ExpiredTimestamp)
        );
    }

    #[test]
    fn unparseable_timestamp_rejected() {
        let now = OffsetDateTime::parse("2026-02-24T18:00:00Z", &Rfc3339).unwrap();
        assert_eq!(
            check_freshness("not-a-date", now, 300),
            Err(SesameError::ExpiredTimestamp)
        );
    }
}
