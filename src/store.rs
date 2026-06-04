//! Reference [`NonceStore`] for a single node (feature `memory-store`).
//!
//! This is the OPEN reference impl (handoff §6). It is correct for one process;
//! it is deliberately *not* the distributed/Redis-backed store, which is the
//! commercial piece in `ba-sesame-ops`. The trait is the open/commercial line.

use crate::error::Replay;
use crate::traits::NonceStore;
use crate::types::{Nonce, UnixTime};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;

/// An in-memory, mutex-guarded replay cache. Bounded by the freshness window:
/// entries older than `ts - window` are evicted opportunistically on each call,
/// so memory use is proportional to the request rate within one window.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    seen: Mutex<HashMap<Vec<u8>, u64>>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of nonces currently retained (after the most recent eviction).
    pub fn len(&self) -> usize {
        self.seen.lock().expect("nonce store mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_record(
        &self,
        nonce: &Nonce,
        ts: UnixTime,
        window: Duration,
    ) -> Result<(), Replay> {
        let mut seen = self.seen.lock().expect("nonce store mutex poisoned");
        // Opportunistic eviction. Entries older than the window can never cause
        // a false replay because the freshness check rejects them first, so
        // dropping them is safe. Production stores should additionally sweep on
        // a timer rather than relying solely on traffic to drive eviction.
        let cutoff = ts.as_secs().saturating_sub(window.as_secs());
        seen.retain(|_, &mut t| t >= cutoff);

        if seen.contains_key(nonce.as_bytes()) {
            return Err(Replay);
        }
        seen.insert(nonce.as_bytes().to_vec(), ts.as_secs());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_ok_replay_rejected() {
        let store = InMemoryNonceStore::new();
        let n = Nonce(vec![1, 2, 3, 4]);
        let w = Duration::from_secs(300);
        assert_eq!(store.check_and_record(&n, UnixTime(1000), w), Ok(()));
        assert_eq!(store.check_and_record(&n, UnixTime(1000), w), Err(Replay));
    }

    #[test]
    fn distinct_nonces_coexist() {
        let store = InMemoryNonceStore::new();
        let w = Duration::from_secs(300);
        assert_eq!(
            store.check_and_record(&Nonce(vec![1]), UnixTime(1000), w),
            Ok(())
        );
        assert_eq!(
            store.check_and_record(&Nonce(vec![2]), UnixTime(1000), w),
            Ok(())
        );
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn old_entries_are_evicted() {
        let store = InMemoryNonceStore::new();
        let w = Duration::from_secs(300);
        store
            .check_and_record(&Nonce(vec![1]), UnixTime(1000), w)
            .unwrap();
        // A much later request evicts the stale entry.
        store
            .check_and_record(&Nonce(vec![2]), UnixTime(5000), w)
            .unwrap();
        assert_eq!(store.len(), 1);
    }
}
