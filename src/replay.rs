// src/sesame/replay.rs
//
// Replay protection. Spec: ANSI/SCTE 130-9 (SESAME) draft v0.5 §8.2.4, §8.5
// items 6–8.
//
// A (key-id, nonce) pair seen within the replay window is rejected. The cache
// is bounded by the window: entries older than the window are pruned, since a
// timestamp that old would already be rejected by the freshness check.
//
// The cache is behind a trait so a shared/distributed backend (e.g. Redis) can
// replace the in-memory impl for horizontally-scaled deployments. NOTE: the
// in-memory cache is per-process and is therefore insufficient across multiple
// POIS nodes, see docs/SESAME.md "Operational Considerations".

use std::collections::HashMap;
use std::sync::Mutex;

/// Replay cache seam. `check_and_remember` atomically tests for a previously
/// seen (key_id, nonce) and records it if new.
pub trait ReplayCache: Send + Sync {
    /// Returns `true` if the (key_id, nonce) is fresh (and records it), or
    /// `false` if it was already seen within the window (a replay).
    /// `now_unix` is the current time in seconds, passed in for testability.
    fn check_and_remember(&self, key_id: &str, nonce: &str, now_unix: i64) -> bool;
}

/// In-memory TTL replay cache, bounded by the replay window.
pub struct InMemoryReplayCache {
    window_secs: i64,
    seen: Mutex<HashMap<(String, String), i64>>, // (key_id, nonce) -> expiry unix secs
}

impl InMemoryReplayCache {
    pub fn new(window_secs: i64) -> Self {
        InMemoryReplayCache {
            window_secs,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Number of live entries (after pruning is opportunistic, this is best-effort).
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_remember(&self, key_id: &str, nonce: &str, now_unix: i64) -> bool {
        let mut map = self.seen.lock().unwrap();
        // Opportunistically prune expired entries so the cache stays bounded by
        // the window regardless of throughput.
        map.retain(|_, &mut expiry| expiry > now_unix);

        let key = (key_id.to_string(), nonce.to_string());
        if map.contains_key(&key) {
            return false; // replay
        }
        map.insert(key, now_unix + self.window_secs);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_accepted_replay_rejected() {
        let c = InMemoryReplayCache::new(300);
        assert!(c.check_and_remember("k", "nonce-1", 1000));
        // same (key, nonce) within window -> replay
        assert!(!c.check_and_remember("k", "nonce-1", 1100));
        // different nonce -> fresh
        assert!(c.check_and_remember("k", "nonce-2", 1100));
        // same nonce different key -> fresh (nonces are per key-id)
        assert!(c.check_and_remember("k2", "nonce-1", 1100));
    }

    #[test]
    fn expired_entries_pruned_and_reusable() {
        let c = InMemoryReplayCache::new(300);
        assert!(c.check_and_remember("k", "n", 1000));
        // After the window passes, the entry is pruned; the nonce frees up.
        // (In practice the freshness check would reject such an old timestamp
        // first; this verifies the cache stays bounded.)
        assert!(c.check_and_remember("k", "n2", 2000));
        assert_eq!(c.len(), 1, "old entry should have been pruned at t=2000");
    }
}
