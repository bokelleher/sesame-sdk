// src/sesame/canonical.rs
//
// Construction of the canonical string that HMAC-SHA256 signs. This is the
// wire-format crux: signer and verifier must produce byte-identical strings.
//
// Spec: ANSI/SCTE 130-9 (SESAME) draft v0.5 §8.2.1–§8.2.3 (request, Tier 1),
// §8.3 (Tier 2 scope binding).
//
// ---------------------------------------------------------------------------
// REQUEST canonical string, fully specified by the paper (§8.2.2 ABNF):
//
//     canonical-string = method LF path LF timestamp LF nonce LF body-hash
//
// Worked example (§8.2.3):
//     POST\n/esam?channel=SportsFeed-East\n2026-02-24T18:00:00Z\n
//     a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n<sha256-hex of body>
//
// body-hash is the lowercase-hex SHA-256 of the request body *as transmitted*.
// When Tier 3 is active the transmitted body is the ciphertext, so this yields
// encrypt-then-MAC. (The paper does not state the ordering explicitly; see
// reconciliation note item 6.)
//
// ---------------------------------------------------------------------------
// [BO] Tier 2 scope binding, UNDERSPECIFIED IN THE PAPER.
//   §8.2.2's ABNF fixes the canonical string at exactly five fields with no
//   scope, but §8.3 says "The scope header SHALL be included in the signature
//   computation." The two are contradictory and there is no Tier-2 worked
//   example. Working construction adopted here (flagged for Bo to ratify in the
//   paper): when X-SESAME-Scope is present, append it as a sixth line equal to
//   the exact header value, e.g. `channel=SportsFeed-East`. Absent in Tier 1.
//   See reconciliation note items 1 and 2.
//
// ---------------------------------------------------------------------------
// [BO] RESPONSE canonical string, NOT SPECIFIED IN THE PAPER.
//   Appendix A.2/A.4 show signed responses, but a response has no HTTP method
//   or request path (the two leading ABNF fields), and §8 gives no response
//   construction. Working construction adopted here (flagged for Bo):
//
//     response-canonical = "RESPONSE" LF correlation LF timestamp LF nonce
//                          LF body-hash [ LF scope ]
//
//   where `correlation` is the acquisitionSignalID being responded to, binding
//   the signed response to the specific request signal it answers (defeats
//   response-substitution). See reconciliation note items 2 and 3.
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};

use crate::message::hex_encode;

const LF: char = '\n';

/// Lowercase-hex SHA-256 of the (possibly-encrypted) body, per §8.2.1.
pub fn body_hash_hex(body: &[u8]) -> String {
    hex_encode(&Sha256::digest(body))
}

/// Build the REQUEST canonical string (§8.2.2). `scope` is `Some` only when
/// Tier 2 is active, in which case it is appended as a sixth line ([BO]).
pub fn request_canonical(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body_hash_hex: &str,
    scope: Option<&str>,
) -> String {
    let mut s = String::with_capacity(method.len() + path.len() + 160);
    s.push_str(method);
    s.push(LF);
    s.push_str(path);
    s.push(LF);
    s.push_str(timestamp);
    s.push(LF);
    s.push_str(nonce);
    s.push(LF);
    s.push_str(body_hash_hex);
    if let Some(scope) = scope {
        s.push(LF);
        s.push_str(scope);
    }
    s
}

/// Build the RESPONSE canonical string ([BO] construction, see header comment).
pub fn response_canonical(
    correlation: &str,
    timestamp: &str,
    nonce: &str,
    body_hash_hex: &str,
    scope: Option<&str>,
) -> String {
    let mut s = String::with_capacity(correlation.len() + 160);
    s.push_str("RESPONSE");
    s.push(LF);
    s.push_str(correlation);
    s.push(LF);
    s.push_str(timestamp);
    s.push(LF);
    s.push_str(nonce);
    s.push(LF);
    s.push_str(body_hash_hex);
    if let Some(scope) = scope {
        s.push(LF);
        s.push_str(scope);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_canonical_matches_paper_worked_example_shape() {
        // §8.2.3 worked example (body-hash abbreviated here).
        let c = request_canonical(
            "POST",
            "/esam?channel=SportsFeed-East",
            "2026-02-24T18:00:00Z",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "deadbeef",
            None,
        );
        assert_eq!(
            c,
            "POST\n/esam?channel=SportsFeed-East\n2026-02-24T18:00:00Z\na1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\ndeadbeef"
        );
    }

    #[test]
    fn tier2_appends_scope_line() {
        let c = request_canonical(
            "POST",
            "/esam",
            "2026-02-24T18:00:00Z",
            "aa",
            "bb",
            Some("channel=SportsFeed-East"),
        );
        assert!(c.ends_with("\nchannel=SportsFeed-East"));
        assert_eq!(c.lines().count(), 6);
    }

    #[test]
    fn body_hash_is_lowercase_hex_sha256() {
        // SHA-256("") known answer.
        assert_eq!(
            body_hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn response_canonical_binds_correlation() {
        let c = response_canonical("sig-20260224-001", "2026-02-24T18:00:00Z", "bb", "cc", None);
        assert!(c.starts_with("RESPONSE\nsig-20260224-001\n"));
    }
}
