# sesame

[![crates.io](https://img.shields.io/crates/v/sesame-esam.svg)](https://crates.io/crates/sesame-esam)
[![docs.rs](https://img.shields.io/docsrs/sesame-esam)](https://docs.rs/sesame-esam)
[![license](https://img.shields.io/crates/l/sesame-esam.svg)](#license)

The canonical implementation of **SESAME** (Secure ESAM Authentication and
Message Encryption), the proposed SCTE 130-9 security layer for the ESAM
interface. Any ESAM participant (POIS, ADS, encoder, packager, decoder) links
this crate and speaks SESAME natively, so a signer and a verifier share one
byte-identical implementation of the wire rules.

Three additive tiers over a Tier-0 baseline, all carried in HTTP headers with
**no ESAM XML schema change**:

| Tier | Capability | Mechanism |
|---|---|---|
| 0 | Unauthenticated baseline | no SESAME headers (backward compatible) |
| 1 | Authentication + integrity | HMAC-SHA256 over a canonical string |
| 2 | Channel-scoped authorization | signed `X-SESAME-Scope`, policy lookup |
| 3 | Payload encryption | AES-256-GCM (96-bit IV, 128-bit tag) |

See [`SESAME.md`](SESAME.md) for the byte-exact wire format (draft v0.5) and
[`test-vectors/`](test-vectors/) for the conformance contract.

> **Other languages:** native **C++** ([`cpp/`](cpp/)), **Python**
> ([`python/`](python/), PyPI `sesame-esam`), and **Go** ([`go/`](go/))
> implementations live alongside this crate, each proven against the same golden
> vectors, so a signer in any of the four and a verifier in any other
> interoperate byte-for-byte. The test vectors are the language-neutral contract
> any implementation validates against.

## Provenance

This crate was extracted byte-for-byte from the [`rust-pois`](https://github.com/bokelleher/rust-pois)
reference implementation, which signs live ESAM traffic in production. It is the
one home of the protocol; `rust-pois` is intended to depend on it. Byte-level
parity is pinned by golden vectors generated from `rust-pois` and reproduced by
`tests/conformance.rs`, so the two cannot silently diverge.

## Design

- **No I/O, no HTTP framework.** `verify_request` / `sign_response` take the
  request parts, the parsed headers, the body, and `now`.
- **The host owns the resources** via injected traits: the key directory
  (`KeyProvider`) and the replay memory (`ReplayCache`). A single-node in-memory
  replay cache ships; distributed stores are the host's concern.
- **RNG is feature-gated.** Verification is RNG-free. Signing needs a fresh
  nonce/IV, so `sign_response` and the IV/nonce helpers sit behind the default-on
  `rng` feature; build `--no-default-features` for a verify-only or embedded host.

## Quick start

```sh
cargo add sesame-esam
```

The crates.io package is [`sesame-esam`](https://crates.io/crates/sesame-esam);
it is imported as `sesame`:

```toml
[dependencies]
sesame = { package = "sesame-esam", version = "0.1" }
```

Verify an inbound request (the POIS side):

```rust
use sesame::{verify_request, RequestContext, SesameConfig, SesameHeaders, Tier};
use sesame::keys::{StaticKeyProvider, HmacKey, ChannelScope};
use sesame::replay::InMemoryReplayCache;
use time::OffsetDateTime;

let provider = StaticKeyProvider::new().with_signing_key(
    "sas-east-01",
    HmacKey(b"shared-secret".to_vec()),
    ChannelScope::list(["SportsFeed-East"]),
);
let replay = InMemoryReplayCache::new(300);

// headers parsed from the request (case-insensitive); see axum_adapter for HeaderMap.
let headers = SesameHeaders::from_lookup(|name| request_header(name));
let ctx = RequestContext { method: "POST", path: "/esam", target_channel: None };

let verified = verify_request(
    &SesameConfig::default(), &provider, &replay,
    &ctx, &headers, body_bytes, OffsetDateTime::now_utc(), Tier::One,
)?;
// verified.plaintext is the ESAM XML; verified.achieved_tier / key_id / scope_channel
# fn request_header(_: &str) -> Option<String> { None }
# let body_bytes = b"";
# Ok::<(), sesame::SesameError>(())
```

Sign an outbound response (the POIS side, requires the `rng` feature):

```rust
use sesame::{sign_response, ResponseParams, SesameConfig, Tier};
# use sesame::keys::StaticKeyProvider;
# let provider = StaticKeyProvider::new();
let params = ResponseParams {
    signing_key_id: "pois-primary",
    correlation: "ap-1:sigid-20260224-001", // the acquisitionSignalID answered
    scope: None,
    tier: Tier::One,
    enc_key_id: None,
};
// let resp = sign_response(&SesameConfig::default(), &provider, &params, xml, now)?;
// attach resp.headers, send resp.body with resp.content_type
```

## Features

| Feature | Default | What it adds |
|---|:--:|--------------|
| `rng` | ✅ | CSPRNG helpers: `sign_response`, `tier3_aead::random_iv`. |
| `serde` |  | Derives on the conformance-vector types (tests/tooling). |
| `axum` |  | `headers_from_map` over `http::HeaderMap`. |

## Open / commercial line

The protocol, the pure core, and the trait seams (`KeyProvider`, `ReplayCache`)
are open (MIT or Apache-2.0), as is the single-node reference replay cache. Operating
SESAME at scale (a distributed replay store, multi-tenant key management and
rotation, audit) is left to separate operational tooling. The traits are the
line.

## Development

```sh
cargo test --features serde            # unit + conformance
cargo clippy --all-features --all-targets
cargo build --no-default-features      # verify-only / RNG-free
```

The golden vectors are regenerated from `rust-pois` via
[`tools/golden-extractor`](tools/golden-extractor/), not in CI; CI asserts the
crate still reproduces the committed vectors.

## License

Code: dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option (extracted from `rust-pois`, originally MIT, © POIS Contributors).
Specification text (`SESAME.md`): [`LICENSE-SPEC`](LICENSE-SPEC).
