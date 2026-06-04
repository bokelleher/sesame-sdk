# sesame

A portable SDK for **SESAME** — the proposed SCTE 130-9 security layer for the
ESAM interface. Any ESAM participant (POIS, ADS, encoder, packager, decoder) can
link this crate and speak SESAME natively, so a signer and a verifier share one
byte-identical implementation of the wire rules.

Three additive tiers, all carried in HTTP headers with **no ESAM XML schema
change**:

1. **Authentication & integrity** — HMAC-SHA256 over a canonical signing string.
2. **Authorization** — channel-scoped, enforced against the resolved key.
3. **Confidentiality** — AES-256-GCM payload encryption.

See [`SESAME.md`](SESAME.md) for the wire format and
[`test-vectors/`](test-vectors/) for the language-neutral conformance contract.

> **Status: scaffold.** This crate is structured per the project handoff, but the
> canonical signing string is **provisional** and must be reconciled against the
> deployed `rust-pois` implementation before it is treated as a published
> standard. See [`SESAME.md`](SESAME.md) §8.

## Design contract

- **Pure, synchronous core.** No I/O, no async runtime, no RNG, no system clock.
  The caller supplies the timestamp, nonce, and (for tier 3) the IV. The same
  crate runs server-side, in a packager, and on an embedded decoder — and the
  conformance vectors are deterministic.
- **The host owns the resources.** The clock, the replay memory, and the key
  directory are injected as traits — `Clock`, `NonceStore`, `KeyResolver`. The
  replay cache is explicitly **not** in the core: a node uses the in-memory
  reference store, a cluster a distributed one, a device a ring buffer.
- **One canonicalization.** Signer and verifier agree byte-for-byte, pinned by
  the JSON test vectors.

## Quick start

```toml
[dependencies]
sesame = "0.1"
```

```rust
use sesame::{sign, verify_signature, RequestParts, KeyId, ChannelScope, Key, Nonce, UnixTime};

let key = Key(b"a-shared-secret".to_vec());
let parts = RequestParts {
    method: "POST",
    target: "/esam/signal",
    key_id: KeyId("encoder-7".into()),
    channel: Some(ChannelScope("wxyz-hd".into())),  // tier 2
};

// Signer (encoder / ADS):
let signed = sign(&parts, &key, &Nonce(vec![0u8; 16]), UnixTime(1_700_000_000), b"<spn/>", None)?;

// Verifier (POIS): the signature is authentic.
let verified = verify_signature("POST", "/esam/signal", &signed.headers, &signed.body, &key)?;
assert_eq!(verified.key_id, KeyId("encoder-7".into()));
# Ok::<(), sesame::SesameError>(())
```

### Full gate with the host seams

`verify_signature` is just tier 1. The recommended order — authenticate,
authorize, check freshness, reject replays — is composed by `Verifier`:

```rust
use std::time::Duration;
use sesame::{Verifier, KeyResolver, Clock, KeyId, Key, ChannelScope, UnixTime, InMemoryNonceStore};

struct Keys;
impl KeyResolver for Keys {
    fn key_for(&self, id: &KeyId) -> Option<Key> {
        (id.0 == "encoder-7").then(|| Key(b"a-shared-secret".to_vec()))
    }
    fn channel_allowed(&self, _id: &KeyId, ch: Option<&ChannelScope>) -> bool {
        ch.map_or(true, |c| c.0 == "wxyz-hd")
    }
}

let verifier = Verifier::new(Keys, || UnixTime(1_700_000_000), InMemoryNonceStore::new())
    .with_window(Duration::from_secs(300));
// verifier.verify(method, target, &headers, &body) -> Verified
```

## Features

| Feature | Default | What it adds |
|---------|:------:|--------------|
| `memory-store` | ✅ | Reference single-node `InMemoryNonceStore` (pure std). |
| `serde` |  | Serde derives on wire types; needed by the conformance harness. |
| `axum` |  | `HeaderSource` for `http::HeaderMap` + a verify helper for `axum::middleware::from_fn`. |
| `cli` |  | The `sesame-gen-vectors` binary. |

The **default build is I/O-free** — the pure crypto/protocol core plus the
in-memory store. HTTP adapters and networked stores are opt-in.

## Where the open/commercial line sits

The protocol, the pure core, the trait seams, and the single-node reference
`NonceStore` are **open (Apache-2.0)**. Operating SESAME at scale — a distributed
replay store, multi-tenant key management and rotation, audit — is the commercial
counterpart (`ba-sesame-ops`). The `NonceStore` trait is the line.

## Development

```sh
cargo test --features serde          # unit + conformance
cargo clippy --all-features
cargo run --features cli --bin sesame-gen-vectors -- --out test-vectors
```

## License

Code: [Apache-2.0](LICENSE). Specification text (`SESAME.md`):
[`LICENSE-SPEC`](LICENSE-SPEC) (provisionally CC0-1.0).
