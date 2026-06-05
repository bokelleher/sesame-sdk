//! Optional HTTP adapter (feature `axum`).
//!
//! The core is framework-agnostic: [`SesameHeaders::from_lookup`] takes a
//! case-insensitive `name -> Option<String>` closure. This module supplies that
//! closure over [`http::HeaderMap`] (the header type axum, hyper, and tower all
//! share), so a Rust ADS/POIS can parse SESAME headers in one call and pass the
//! result to [`crate::verify_request`].
//!
//! ```ignore
//! use axum::{extract::Request, body::Bytes};
//! use sesame::{verify_request, axum_adapter::headers_from_map, RequestContext,
//!              SesameConfig, Tier};
//!
//! let (parts, body) = req.into_parts();
//! let bytes: Bytes = /* buffer the body */;
//! let headers = headers_from_map(&parts.headers);
//! let ctx = RequestContext { method: parts.method.as_str(), path: parts.uri.path(), target_channel: None };
//! let verified = verify_request(&cfg, &provider, &replay, &ctx, &headers, &bytes, now, Tier::One)?;
//! ```

use crate::message::SesameHeaders;
use http::HeaderMap;

/// Parse [`SesameHeaders`] from an [`http::HeaderMap`]. Header-name lookup is
/// case-insensitive (HTTP semantics); non-UTF-8 header values are treated as
/// absent.
pub fn headers_from_map(map: &HeaderMap) -> SesameHeaders {
    SesameHeaders::from_lookup(|name| {
        map.get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    })
}
