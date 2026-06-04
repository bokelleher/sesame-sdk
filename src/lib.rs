//! # SESAME
//!
//! A portable SDK for **SESAME** — the proposed SCTE 130-9 security layer for
//! the ESAM interface. Three additive tiers, all carried in HTTP headers with
//! **no ESAM XML schema change**:
//!
//! 1. **Tier 1 — authentication & integrity:** HMAC-SHA256 over a canonical
//!    signing string ([`auth::sign`] / [`auth::verify_signature`]).
//! 2. **Tier 2 — authorization:** channel-scoped, enforced by the host's
//!    [`KeyResolver`](traits::KeyResolver).
//! 3. **Tier 3 — confidentiality:** AES-256-GCM payload encryption
//!    ([`cipher`]).
//!
//! ## Design contract
//!
//! - **Pure and synchronous core.** No I/O, no async runtime, no RNG, no system
//!   clock. Caller supplies the timestamp, nonce, and (for tier 3) IV. This is
//!   what makes the same crate run server-side, in a packager, and on an
//!   embedded decoder — and what makes the conformance vectors deterministic.
//! - **Host owns the resources.** The clock, the replay memory, and the key
//!   directory are injected as the [`Clock`](traits::Clock),
//!   [`NonceStore`](traits::NonceStore), and [`KeyResolver`](traits::KeyResolver)
//!   traits. The replay cache is explicitly *not* in the core (handoff §5).
//! - **One canonicalization.** Signer and verifier agree byte-for-byte on the
//!   [`canonical`] signing string, or they do not interoperate at all. The
//!   language-neutral JSON vectors in `test-vectors/` pin it.
//!
//! ## Verifying end to end
//!
//! The primitives are separate on purpose; a constrained host can use only what
//! it needs. The recommended order, which [`Verifier`] performs for you:
//!
//! 1. [`verify_signature`] — authenticate (tier 1) and parse tier 2/3 metadata.
//! 2. channel authorization (tier 2) via [`KeyResolver::channel_allowed`].
//! 3. [`check_freshness`] — reject stale/future-dated requests.
//! 4. [`NonceStore::check_and_record`] — reject replays.
//! 5. [`auth::decrypt_body`] — recover the plaintext (tier 3 only).
//!
//! ```
//! use sesame::{sign, verify_signature, RequestParts, KeyId, ChannelScope, Key, Nonce, UnixTime};
//!
//! let key = Key(b"a-shared-secret".to_vec());
//! let parts = RequestParts {
//!     method: "POST",
//!     target: "/esam/signal",
//!     key_id: KeyId("encoder-7".into()),
//!     channel: Some(ChannelScope("wxyz-hd".into())),
//! };
//!
//! // Signer side (e.g. the encoder/ADS):
//! let signed = sign(&parts, &key, &Nonce(vec![0u8; 16]), UnixTime(1_700_000_000), b"<spn/>", None).unwrap();
//!
//! // Verifier side (e.g. the POIS): signature is authentic.
//! let verified = verify_signature("POST", "/esam/signal", &signed.headers, &signed.body, &key).unwrap();
//! assert_eq!(verified.key_id, KeyId("encoder-7".into()));
//! ```
//!
//! > **Status:** scaffold. The canonical signing-string layout in [`canonical`]
//! > is *provisional* and must be reconciled against the deployed rust-pois
//! > implementation before it is treated as a published standard (handoff §3).

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod auth;
pub mod canonical;
pub mod cipher;
pub mod encoding;
pub mod error;
pub mod headers;
pub mod traits;
pub mod types;
pub mod verifier;

#[cfg(feature = "memory-store")]
pub mod store;

#[cfg(feature = "axum")]
pub mod axum_adapter;

#[cfg(feature = "serde")]
pub mod vectors;

// ---- Curated top-level re-exports ----

pub use auth::{check_freshness, decrypt_body, sign, verify_signature};
pub use error::{Replay, SesameError};
pub use headers::HeaderSource;
pub use traits::{Clock, KeyResolver, NonceStore};
pub use types::{
    header, ChannelScope, EncryptionInfo, EncryptionParams, Key, KeyId, Nonce, RequestParts,
    Signed, UnixTime, Verified, ENC_AES_256_GCM, VERSION,
};
pub use verifier::{Verifier, DEFAULT_WINDOW};

#[cfg(feature = "memory-store")]
pub use store::InMemoryNonceStore;
