//! Optional composition helper that wires the three host seams together.
//!
//! The primitives ([`verify_signature`](crate::verify_signature),
//! [`check_freshness`](crate::check_freshness), and the host's
//! [`NonceStore`](crate::traits::NonceStore)) are deliberately separate so a
//! constrained host can use exactly the pieces it needs. [`Verifier`] is the
//! convenience for the common case: given a [`KeyResolver`], a [`Clock`], and a
//! [`NonceStore`], it runs the full gate in the correct order:
//!
//! 1. resolve the key from `X-Sesame-Key-Id`,
//! 2. verify the tier 1 signature,
//! 3. enforce tier 2 channel authorization,
//! 4. check freshness against the clock,
//! 5. check-and-record the nonce for replay.
//!
//! It is still synchronous and I/O-free in itself, any I/O lives inside the
//! injected traits.

use crate::auth::{check_freshness, decrypt_body, verify_signature};
use crate::error::SesameError;
use crate::headers::HeaderSource;
use crate::traits::{Clock, KeyResolver, NonceStore};
use crate::types::{header, Key, KeyId, Verified};
use core::time::Duration;

/// Default freshness window: 5 minutes each side.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Ties a key directory, a clock, and a replay store into one verify call.
pub struct Verifier<R, C, S> {
    pub resolver: R,
    pub clock: C,
    pub store: S,
    pub window: Duration,
}

// Manual Debug so the seam types need not be Debug, and so nothing inside the
// key directory or replay store is ever printed.
impl<R, C, S> core::fmt::Debug for Verifier<R, C, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verifier")
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl<R: KeyResolver, C: Clock, S: NonceStore> Verifier<R, C, S> {
    pub fn new(resolver: R, clock: C, store: S) -> Self {
        Self {
            resolver,
            clock,
            store,
            window: DEFAULT_WINDOW,
        }
    }

    /// Override the freshness window.
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Run the full SESAME gate. On `Ok`, the request is authentic, authorized,
    /// fresh, and not a replay.
    pub fn verify(
        &self,
        method: &str,
        target: &str,
        headers: &impl HeaderSource,
        body: &[u8],
    ) -> Result<Verified, SesameError> {
        let key = self.resolve_key(headers)?;
        let verified = verify_signature(method, target, headers, body, &key)?;

        if !self
            .resolver
            .channel_allowed(&verified.key_id, verified.channel.as_ref())
        {
            return Err(SesameError::Unauthorized {
                channel: verified
                    .channel
                    .as_ref()
                    .map(|c| c.0.clone())
                    .unwrap_or_default(),
            });
        }

        check_freshness(verified.timestamp, self.clock.now(), self.window)?;
        self.store
            .check_and_record(&verified.nonce, verified.timestamp, self.window)?;
        Ok(verified)
    }

    /// Decrypt a tier 3 body after a successful [`verify`](Self::verify).
    /// Re-resolves the key so the caller need not hold it.
    pub fn decrypt(
        &self,
        headers: &impl HeaderSource,
        verified: &Verified,
        body: &[u8],
    ) -> Result<Vec<u8>, SesameError> {
        let key = self.resolve_key(headers)?;
        decrypt_body(verified, &key, body)
    }

    fn resolve_key(&self, headers: &impl HeaderSource) -> Result<Key, SesameError> {
        let key_id = KeyId(
            headers
                .get(header::KEY_ID)
                .ok_or(SesameError::MissingHeader(header::KEY_ID))?
                .to_string(),
        );
        self.resolver
            .key_for(&key_id)
            .ok_or(SesameError::UnknownKey(key_id.0))
    }
}
