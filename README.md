# SESAME

[![CI](https://github.com/bokelleher/sesame-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/bokelleher/sesame-sdk/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sesame-esam.svg?label=crates.io)](https://crates.io/crates/sesame-esam)
[![PyPI](https://img.shields.io/pypi/v/sesame-esam?label=PyPI)](https://pypi.org/project/sesame-esam/)
[![docs.rs](https://img.shields.io/docsrs/sesame-esam?label=docs.rs)](https://docs.rs/sesame-esam)
[![license](https://img.shields.io/crates/l/sesame-esam.svg)](#license)

**SESAME** (Secure ESAM Authentication and Message Encryption) is the proposed
SCTE 130-9 security layer for the ESAM interface. It secures the two-party HTTP
exchange between an ESAM client (encoder, packager, ADS) and an ESAM server
(POIS) using three additive tiers, all carried in HTTP headers with **no change
to any ESAM XML schema**.

This repository is the home of the standard **and** its reference
implementations in four languages, every one of which is proven byte-for-byte
against a single shared set of conformance vectors. A signer written in any
language and a verifier written in any other interoperate exactly.

| Tier | Capability | Mechanism |
|---|---|---|
| 0 | Unauthenticated baseline | no SESAME headers (backward compatible) |
| 1 | Authentication + integrity | HMAC-SHA256 over a canonical signing string |
| 2 | Channel-scoped authorization | signed `X-SESAME-Scope`, policy lookup |
| 3 | Payload encryption | AES-256-GCM (96-bit IV, 128-bit tag) |

Plus signed responses, which authenticate the POIS's conditioning decision so a
forged or tampered blackout/avail/redirect fails verification.

## Implementations

| Language | Install | Source | Distribution |
|---|---|---|---|
| **Rust** | `cargo add sesame-esam` | [`src/`](src/) | [crates.io](https://crates.io/crates/sesame-esam) |
| **C++** | `find_package(sesame)` (CMake / vcpkg / Conan) | [`cpp/`](cpp/) | [`cpp/`](cpp/#install-and-consume) |
| **Python** | `pip install sesame-esam` | [`python/`](python/) | [PyPI](https://pypi.org/project/sesame-esam/) |
| **Go** | `go get github.com/bokelleher/sesame-sdk/go` | [`go/`](go/) | Go module |

The deployed [`rust-pois`](https://github.com/bokelleher/rust-pois) POIS server
runs SESAME in production by depending on the Rust crate, so the protocol lives
in exactly one place per language and there is no parallel copy to drift.

## The test vectors are the contract

[`test-vectors/tier1.json`](test-vectors/) and
[`test-vectors/tier3.json`](test-vectors/) are the language-neutral conformance
contract. They are generated from the deployed `rust-pois` implementation and
pin the exact bytes on the wire (canonical strings, HMAC signatures, GCM
associated data, `ciphertext||tag`). **An implementation is conformant if, and
only if, it reproduces every `expected_*` value byte-for-byte.** Each SDK proves
exactly that, in CI:

| | Rust | C++ | Python | Go |
|---|---|---|---|---|
| Conformance | `cargo test` | `ctest` | `pytest` | `go test` |

See [`SESAME.md`](SESAME.md) for the byte-exact wire format (draft v0.5),
[`test-vectors/README.md`](test-vectors/README.md) for how to consume the
vectors from any language, and [`CONTRIBUTING.md`](CONTRIBUTING.md) to add a new
language implementation.

## Quick start (Rust)

```sh
cargo add sesame-esam   # imported as `sesame`
```

Verify an inbound request (the POIS side):

```rust
use sesame::{verify_request, RequestContext, SesameConfig, SesameHeaders, Tier};
use sesame::keys::{StaticKeyProvider, HmacKey, ChannelScope};
use sesame::replay::InMemoryReplayCache;
use time::OffsetDateTime;

let provider = StaticKeyProvider::new().with_signing_key(
    "sas-east-01", HmacKey(b"shared-secret".to_vec()),
    ChannelScope::list(["SportsFeed-East"]));
let replay = InMemoryReplayCache::new(300);

let headers = SesameHeaders::from_lookup(|name| request_header(name));
let ctx = RequestContext { method: "POST", path: "/esam", target_channel: None };

let verified = verify_request(&SesameConfig::default(), &provider, &replay,
    &ctx, &headers, body_bytes, OffsetDateTime::now_utc(), Tier::One)?;
// verified.plaintext is the ESAM XML; verified.achieved_tier / key_id / scope_channel
# fn request_header(_: &str) -> Option<String> { None }
# let body_bytes = b"";
# Ok::<(), sesame::SesameError>(())
```

Sign an outbound response (requires the default-on `rng` feature):

```rust
use sesame::{sign_response, ResponseParams, SesameConfig, Tier};
# use sesame::keys::StaticKeyProvider;
# let provider = StaticKeyProvider::new();
let params = ResponseParams {
    signing_key_id: "pois-primary",
    correlation: "ap-1:sigid-20260224-001", // the acquisitionSignalID answered
    scope: None, tier: Tier::One, enc_key_id: None,
};
// let resp = sign_response(&SesameConfig::default(), &provider, &params, xml, now)?;
```

The C++, Python, and Go SDKs expose the same shape (`verify_request` /
`sign_response`, the `KeyProvider` and `ReplayCache` seams, Tier 0-3); see each
language's README for idiomatic usage.

## Design

Common to every implementation:

- **No I/O, no HTTP framework.** `verify_request` / `sign_response` take the
  request parts, parsed headers, body, and `now`.
- **The host owns the resources** via injected seams: the key directory
  (`KeyProvider`) and the replay memory (`ReplayCache`). A single-node in-memory
  replay cache ships; distributed stores are the host's concern.
- **Verification is RNG-free.** Only signing needs a fresh nonce/IV (gated behind
  the Rust `rng` feature; the other SDKs draw from the OS CSPRNG when signing).

## Provenance

The Rust crate was extracted byte-for-byte from the deployed `rust-pois`
reference implementation, which signs live ESAM traffic in production. The
golden vectors are generated from `rust-pois` (via
[`tools/golden-extractor`](tools/golden-extractor/)); the C++, Python, and Go
SDKs were then written independently and validated against those same vectors.
Four from-scratch implementations agreeing on the wire is the strongest evidence
that SESAME is a real, implementable standard.

## Where the open/commercial line sits

The protocol, the implementations, and the trait seams (`KeyProvider`,
`ReplayCache`) are open. Operating SESAME at scale (a distributed replay store,
multi-tenant key management and rotation, audit) is left to separate operational
tooling. The seams are the line.

## Status

Pre-1.0 by design: the wire spec is draft v0.5, not yet a ratified SCTE
standard. `1.0` waits on SCTE formalization. The bar the project set for "a real
standard, a second implementer can adopt it in an afternoon" is already met four
times over.

Release history is in [CHANGELOG.md](CHANGELOG.md). Note that 0.1.2 and earlier
are superseded and yanked; use 0.1.3 or later.

## Benchmarks

Two harnesses, measuring different things. `cargo bench` runs Criterion
micro-benchmarks over the individual cryptographic operations. `cargo bench
--bench load` runs a sustained-load harness that exercises the full inbound
verify path with the replay cache in the request path, reporting per-request
cost against cache occupancy, throughput under concurrency, payload
sensitivity, and the cost of rejecting an invalid signature.

The second one exists because the first cannot see the replay cache, and the
replay cache is where the latency budget is actually won or lost. See
[Cache maintenance](SESAME.md#cache-maintenance) in the spec.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option (the Rust core was extracted from `rust-pois`, originally MIT, © POIS
Contributors). Specification text (`SESAME.md`): [`LICENSE-SPEC`](LICENSE-SPEC).
