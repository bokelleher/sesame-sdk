//! Optional HTTP adapter (feature `axum`).
//!
//! The core is framework-agnostic: [`SesameHeaders::from_lookup`] takes a
//! case-insensitive `name -> Option<String>` closure, and [`crate::RequestContext`]
//! takes the request-target as a plain string. This module supplies both over the
//! `http` crate types that axum, hyper, and tower all share, so a Rust ADS/POIS
//! derives neither by hand.
//!
//! Deriving the request-target by hand is the one step of a SESAME integration
//! that fails silently when it is wrong: [`Uri::path`] compiles, works, and
//! passes every golden vector while leaving the query string unsigned. Use
//! [`request_target`].
//!
//! ```ignore
//! use axum::{body::Bytes, extract::OriginalUri, http::Request};
//! use sesame::{axum_adapter::{headers_from_map, request_target},
//!              verify_request, RequestContext, SesameConfig, Tier};
//!
//! // Take the URI from `OriginalUri`, not `Request::uri()`: under a nested
//! // router the latter has the nesting prefix stripped, so it is not the
//! // target the peer signed.
//! let OriginalUri(uri) = original_uri;
//! let (parts, body) = req.into_parts();
//! let bytes: Bytes = /* buffer the body */;
//!
//! let headers = headers_from_map(&parts.headers);
//! let ctx = RequestContext {
//!     method: parts.method.as_str(),
//!     // path + query. `uri.path()` here would leave every query
//!     // parameter unsigned and modifiable in transit.
//!     path: request_target(&uri),
//!     target_channel: None,
//! };
//! let verified = verify_request(&cfg, &provider, &replay, &ctx, &headers, &bytes, now, Tier::One)?;
//! ```

use crate::message::SesameHeaders;
use http::{HeaderMap, Uri};

/// Parse [`SesameHeaders`] from an [`http::HeaderMap`]. Header-name lookup is
/// case-insensitive (HTTP semantics); non-UTF-8 header values are treated as
/// absent.
///
/// Only the first value of a repeated header is used, matching
/// [`HeaderMap::get`]. SESAME headers are not defined as list-valued, and a
/// duplicate is a malformed message; see the header-canonicalization note in
/// `SESAME.md`.
pub fn headers_from_map(map: &HeaderMap) -> SesameHeaders {
    SesameHeaders::from_lookup(|name| {
        map.get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    })
}

/// The exact request-target to sign: origin-form `absolute-path [ "?" query ]`,
/// byte-for-byte as received.
///
/// This is the second field of the Tier-1 canonical string. It is deliberately
/// **not** the RFC 3986 `path` component: the query is covered by the signature
/// so that an intermediary cannot alter it without invalidating the signature.
/// [`Uri::path`] stops at the `?`, and a verifier built on it accepts a request
/// whose query has been rewritten in transit.
///
/// No decoding and no normalisation is applied. Percent-encoding is preserved
/// exactly as received, because signer and verifier must hash identical bytes.
///
/// Pass the URI **as received**. Under a nested router take it from axum's
/// `OriginalUri` extractor rather than `Request::uri()`, which has the nesting
/// prefix stripped.
///
/// Byte-identical to the derivation used by the `rust-pois` reference
/// implementation in `handle_esam_impl`; see the equivalence test below.
pub fn request_target(uri: &Uri) -> &str {
    uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation `rust-pois` performs inline in `handle_esam_impl`
    /// (`src/main.rs`), transcribed verbatim. `request_target` must agree with
    /// it for every input, or the SDK and the reference implementation would
    /// sign different canonical strings.
    fn rust_pois_derivation(uri: &Uri) -> String {
        uri.path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string())
    }

    const MATRIX: &[&str] = &[
        "/esam",
        "/esam?channel=SportsFeed-East",
        "/esam?channel=SportsFeed-East&priority=high",
        "/esam/channel/SportsFeed-East",
        "/esam?",
        "/esam?channel=Sports%20Feed",
        "/esam?channel=Sports+Feed",
        "/esam?a=1&a=2",
        "/",
        "http://pois.example/esam?channel=SportsFeed-East",
    ];

    #[test]
    fn agrees_with_rust_pois_derivation() {
        for raw in MATRIX {
            let uri: Uri = raw.parse().expect(raw);
            assert_eq!(
                request_target(&uri),
                rust_pois_derivation(&uri),
                "diverged from the reference implementation for {raw:?}"
            );
        }
    }

    #[test]
    fn query_is_included() {
        let uri: Uri = "/esam?channel=SportsFeed-East".parse().unwrap();
        assert_eq!(request_target(&uri), "/esam?channel=SportsFeed-East");
        // The defect this function exists to prevent.
        assert_ne!(request_target(&uri), uri.path());
    }

    #[test]
    fn every_query_parameter_is_covered() {
        let uri: Uri = "/esam?channel=SportsFeed-East&priority=high".parse().unwrap();
        assert_eq!(
            request_target(&uri),
            "/esam?channel=SportsFeed-East&priority=high"
        );
    }

    #[test]
    fn percent_encoding_is_preserved_not_decoded() {
        let uri: Uri = "/esam?channel=Sports%20Feed".parse().unwrap();
        assert_eq!(request_target(&uri), "/esam?channel=Sports%20Feed");
        assert!(!request_target(&uri).contains(' '));
    }

    #[test]
    fn absolute_form_yields_origin_form_target() {
        let uri: Uri = "http://pois.example/esam?channel=A".parse().unwrap();
        assert_eq!(request_target(&uri), "/esam?channel=A");
    }

    #[test]
    fn no_query_matches_path() {
        let uri: Uri = "/esam".parse().unwrap();
        assert_eq!(request_target(&uri), "/esam");
        assert_eq!(request_target(&uri), uri.path());
    }
}
