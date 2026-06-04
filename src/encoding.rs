//! Small, dependency-light encoding helpers used on the wire.
//!
//! base64 is the standard alphabet *with* padding (RFC 4648 §4). Hex is
//! lowercase. Both choices are part of the wire contract and are pinned by the
//! conformance vectors.

use crate::error::SesameError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// base64-encode (standard alphabet, padded).
pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// base64-decode, mapping any failure to a [`SesameError::MalformedHeader`].
pub fn b64_decode(header: &'static str, s: &str) -> Result<Vec<u8>, SesameError> {
    STANDARD
        .decode(s.as_bytes())
        .map_err(|_| SesameError::MalformedHeader {
            header,
            reason: "invalid base64",
        })
}

/// Lowercase hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Lowercase/uppercase hex decoding. Used by the conformance harness to read
/// key/nonce/IV material out of the JSON vectors.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, SesameError> {
    if s.len() % 2 != 0 {
        return Err(SesameError::MalformedHeader {
            header: "<hex>",
            reason: "odd-length hex string",
        });
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = val(pair[0]);
        let lo = val(pair[1]);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => {
                return Err(SesameError::MalformedHeader {
                    header: "<hex>",
                    reason: "invalid hex digit",
                })
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let data = [0x00u8, 0x0f, 0xff, 0xa5];
        assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
        assert_eq!(hex_decode("00FF").unwrap(), vec![0x00, 0xff]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn base64_round_trips() {
        let data = b"sesame";
        let enc = b64_encode(data);
        assert_eq!(b64_decode("X-Test", &enc).unwrap(), data);
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(b64_decode("X-Test", "not valid base64 !!!").is_err());
    }
}
