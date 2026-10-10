# Changelog

All notable changes to the SESAME SDK. The wire protocol is specified in
[SESAME.md](SESAME.md); the golden vectors in `test-vectors/` are the
interoperability contract; a release may add vectors but never alters a
previously published `expected_*` value.

## [0.1.4.post1] - 2026-10-10 (Python only)

Documentation re-release of the Python package; no code change from 0.1.4. The
README now cites the published SESAME paper (SET IJBE vol. 12, 2026,
DOI 10.18580/setijbe.2026.6). This is also the first PyPI upload since Python
0.1.1 (Python 0.1.4 was tagged but never uploaded). Python 0.1.1 already carried
the replay-cache fix; relative to it, this release adds the 0.1.4 request-target
and version-handling documentation and fixes `sesame.__version__`, which
reported `0.1.0` in 0.1.1. Python 0.1.1 is now yanked on PyPI.

## [0.1.4] - 2026-08-20

Hardening release. No wire-format change: every previously published golden
vector reproduces byte-for-byte, and one vector is added. All API changes are
additive.

### Fixed

- **`axum_adapter` request-target example dropped the query.** The module's only
  worked HTTP-integration example built the canonical string's second field from
  `uri.path()`, which stops at the `?`, leaving the query string unsigned and
  modifiable in transit. It compiled, worked, and passed every golden vector
  while being query-blind, exactly the Tier 1 threat the signature exists to
  close. The example now derives the full request-target and takes it from
  `OriginalUri`.

### Added

- **`axum_adapter::request_target(&Uri) -> &str`** (feature `axum`): the correct
  origin-form request-target (`absolute-path [ "?" query ]`, byte-for-byte, no
  normalization) so integrators do not hand-roll the one derivation that fails
  silently when wrong. A test asserts byte-equality with the `rust-pois`
  reference derivation across a URI matrix (query, multi-param, percent-encoding,
  absolute-form).
- **Golden vector `tier1 request, query component signed`** isolates a Tier-1
  request bearing a query with no scope, pinning that the query is inside the
  signature independently of Tier 2. Reproduced byte-for-byte by all four SDKs.

### Security

- **Request-target scope stated normatively.** `SESAME.md` now specifies that the
  second canonical field is the request-target including the query, explicitly
  not the RFC 3986 `path` component, taken as transmitted with no normalization.
- **Protocol version handling stated normatively (downgrade closure).** New
  `SESAME.md` "Protocol version" section fixes byte-exact `X-SESAME-Version`
  equality as a security invariant: the header is not in the canonical string and
  so is unauthenticated at Tiers 1 and 2, which makes strict equality a
  fail-closed rejection rather than a downgrade vector. Extension proceeds by
  binding new material into the canonical string, not by version negotiation; a
  verifier that ever accepts more than one version SHALL bind the version into
  the canonical string first. Each SDK's version check carries a matching guard
  comment. Behavior is unchanged: all four SDKs already compared byte-exact.

### Documented

- Python `RequestContext.path` now documents that it is the full request-target
  (path and query), matching the Rust, Go, and C++ SDKs.

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

### Deprecated

- **0.1.2 and earlier are superseded; use 0.1.3.** Their replay cache degrades
  under sustained load, so there is no reason to select an earlier version.
  0.1.3 is a drop-in replacement: no API changes, and the golden conformance
  vectors are unchanged.

## [0.1.2] and earlier

See the git history and the GitHub releases page.
