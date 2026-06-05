# golden-extractor

Generates the authoritative conformance vectors in `../../test-vectors/`
(`tier1.json`, `tier3.json`) **from the deployed `rust-pois` implementation**,
so the `sesame` crate's `tests/conformance.rs` can prove byte-for-byte parity
with what production actually puts on the wire.

The vectors are deterministic: fixed key, IV, nonce, and timestamp inputs are
fed to rust-pois's own `canonical`, `tier1_hmac`, and `tier3_aead` functions.

## Regenerating

The extractor compiles rust-pois's deterministic SESAME source standalone (no
DB/axum). Copy the four leaf modules from a `rust-pois` checkout, then run:

```sh
mkdir -p src/sesame
cp /path/to/rust-pois/src/sesame/{canonical,message,tier1_hmac,tier3_aead}.rs src/sesame/
printf 'pub mod message;\npub mod canonical;\npub mod tier1_hmac;\npub mod tier3_aead;\n' > src/sesame/mod.rs
# fix the in-crate module path the copied files use:
sed -i 's/crate::sesame::/crate::/g' src/sesame/*.rs
cargo run   # writes ../../test-vectors/tier1.json and tier3.json
```

`src/sesame/` is intentionally not committed here: it is a verbatim copy of
rust-pois source (MIT, © POIS Contributors) pulled in only at regeneration time.
`src/main.rs` and `Cargo.toml` are the harness.

## When to regenerate

Only when rust-pois changes the wire format (canonical string, AAD, encodings,
header semantics). That is a deliberate, reviewed event: regenerate, and the
conformance test will tell you whether the `sesame` crate still matches.
