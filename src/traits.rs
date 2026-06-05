//! The injected seams that keep the core portable (handoff §5).
//!
//! The core owns the *rules* (the canonical signing string, the freshness
//! window, the replay-rejection logic, the pure crypto). The host owns the
//! *resources* (the clock, the replay memory, the key directory). These three
//! traits are that boundary.
//!
//! All three are synchronous on purpose: the core never imports an async
//! runtime, so it drops into an embedded decoder as cleanly as into an Axum
//! service. A host whose store is genuinely async (e.g. Redis) does the await
//! in its own code and calls [`NonceStore::check_and_record`] from there, the
//! freshness check is a host-invoked step, not something the core drives.

use crate::error::Replay;
use crate::types::{ChannelScope, Key, KeyId, Nonce, UnixTime};
use core::time::Duration;

/// Source of "now". Injected so the core has no dependency on the system clock
/// (and so tests/vectors are deterministic).
pub trait Clock {
    fn now(&self) -> UnixTime;
}

impl<F> Clock for F
where
    F: Fn() -> UnixTime,
{
    fn now(&self) -> UnixTime {
        self()
    }
}

/// The host's replay memory. The core decides *whether* a nonce is fresh enough
/// to bother recording (via the freshness window); the store decides whether it
/// has been *seen* within that window.
///
/// Implementations:
/// - in-memory single-node: [`crate::store::InMemoryNonceStore`] (feature
///   `memory-store`), the open reference;
/// - distributed (Redis, etc.): lives in the commercial `ba-sesame-ops`, not
///   here (handoff §6).
///
/// `check_and_record` MUST be atomic: a concurrent second presentation of the
/// same `(nonce, ts)` within `window` must see exactly one success.
pub trait NonceStore {
    /// Record `nonce` as seen at `ts`, or reject it as a [`Replay`] if it was
    /// already recorded within `window`. Entries older than `window` MAY be
    /// evicted, they can never cause a false replay because the freshness
    /// check rejects them first.
    fn check_and_record(&self, nonce: &Nonce, ts: UnixTime, window: Duration)
        -> Result<(), Replay>;
}

/// Resolves a key id to its key material and authorization scope (tiers 1 & 2).
///
/// This deliberately separates "what is the key" from "is the key allowed on
/// this channel", rather than folding channel into key lookup. The two
/// questions have different answers from different sources in real deployments
/// (a key directory vs. an entitlement table), and keeping them apart lets a
/// tier-1-only host ignore channels entirely.
pub trait KeyResolver {
    /// The key for `key_id`, or `None` if unknown.
    fn key_for(&self, key_id: &KeyId) -> Option<Key>;

    /// Tier 2: is `key_id` authorized to act on `channel`? The default allows
    /// everything, which is correct for tier-1-only deployments. `channel` is
    /// `None` when the request carried no channel scope.
    fn channel_allowed(&self, _key_id: &KeyId, _channel: Option<&ChannelScope>) -> bool {
        true
    }
}
