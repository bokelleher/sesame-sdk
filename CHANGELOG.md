# Changelog

All notable changes to the SESAME SDK. The wire protocol is specified in
[SESAME.md](SESAME.md); the golden vectors in `test-vectors/` are the
interoperability contract and are unchanged by any release below.

## [0.1.3] - 2026-07-21

### Fixed

- **`InMemoryReplayCache` per-request cost no longer grows with cache
  occupancy.** The cache swept every expired entry on each
  `check_and_remember`, so per-request cost was proportional to the number of
  live entries, which under a 300 s window is itself proportional to request
  rate. Because the sweep ran under the cache mutex, throughput did not scale
  with added concurrency. The sweep is now performed at most once per
  wall-clock second, making it O(1) amortized per request.

  After the fix, measured on a 16-core Xeon E5-2680 v4 (AES-NI, no SHA
  extensions), Tier 1, 1 KiB body, unique nonce per request:

  | Threads | Throughput | p50 | p99 |
  |---|---|---|---|
  | 1 | 40,111 req/s | 23.4 µs | 39.7 µs |
  | 2 | 80,222 req/s | 21.2 µs | 41.0 µs |
  | 4 | 143,899 req/s | 23.9 µs | 45.4 µs |
  | 8 | 242,823 req/s | 24.1 µs | 49.1 µs |

  Per-request latency is now flat as the cache fills from 5,000 to 60,000 live
  entries, where previously it rose with occupancy.

  The same fix is applied to the C++, Python, and Go SDKs.

  Deployments on 0.1.2 or earlier that run sustained load with high nonce
  cardinality should upgrade: the effect grows with both request rate and
  thread count.

### Changed

- `InMemoryReplayCache::len()` (and the C++, Python, and Go equivalents) may now
  count entries that have expired but not yet been swept. The value was always
  documented as best-effort; it is now best-effort over a window of up to one
  second. Replay correctness is unaffected: a lingering entry can only cause a
  rejection, never a false acceptance.
- Memory bound widens from one replay window of traffic to one window plus one
  second.

### Added

- `benches/load.rs`, a sustained-load harness measuring the full inbound verify
  path with the replay cache in the request path, under concurrency. Run with
  `cargo bench --bench load`.

## [0.1.2] and earlier

See the git history and the GitHub releases page.
