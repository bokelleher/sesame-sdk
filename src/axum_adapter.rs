//! Optional HTTP adapter (feature `axum`).
//!
//! This is the thin, common-case glue for a Rust ADS/POIS: a [`HeaderSource`]
//! impl over [`http::HeaderMap`] (the header type axum, hyper, and tower all
//! share) plus [`verify_request`], a synchronous helper that slots into
//! `axum::middleware::from_fn`.
//!
//! It intentionally does **not** ship a hand-rolled tower `Layer`/`Service`.
//! The core is synchronous and storage-agnostic; a full middleware would have
//! to make policy choices (where the key directory lives, how the body is
//! buffered, how a rejection is rendered) that belong to the host. `from_fn`
//! with this helper keeps those choices in the host's hands. A first-party
//! `Layer` is a documented follow-up once a real ADS partner pins the policy.
//!
//! ```ignore
//! use axum::{middleware::from_fn_with_state, body::Bytes, extract::{State, Request}};
//! use sesame::{Verifier, axum_adapter::verify_request};
//!
//! async fn sesame_guard(State(v): State<Arc<Verifier<..>>>, req: Request, next: Next) -> Response {
//!     let (parts, body) = req.into_parts();
//!     let bytes = Bytes::/* buffer */;
//!     match verify_request(&v, parts.method.as_str(), parts.uri.path(), &parts.headers, &bytes) {
//!         Ok(_verified) => next.run(Request::from_parts(parts, Body::from(bytes))).await,
//!         Err(e) => (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
//!     }
//! }
//! ```

use crate::error::SesameError;
use crate::headers::HeaderSource;
use crate::traits::{Clock, KeyResolver, NonceStore};
use crate::types::Verified;
use crate::verifier::Verifier;
use http::HeaderMap;

impl HeaderSource for HeaderMap {
    fn get(&self, name: &str) -> Option<&str> {
        HeaderMap::get(self, name).and_then(|v| v.to_str().ok())
    }
}

/// Run the full SESAME gate against an [`http::HeaderMap`] and body. A thin
/// wrapper over [`Verifier::verify`] so callers don't have to name the
/// `HeaderSource` trait.
pub fn verify_request<R, C, S>(
    verifier: &Verifier<R, C, S>,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Verified, SesameError>
where
    R: KeyResolver,
    C: Clock,
    S: NonceStore,
{
    verifier.verify(method, target, headers, body)
}
