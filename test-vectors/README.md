# SESAME conformance test vectors

These JSON files are the **language-neutral conformance contract** for SESAME.
They are the single most valuable artifact in this repository for cross-language
adoption: an implementation in Go, Python, C++, or anything else is conformant
when it reproduces every `expected_*` value from the given inputs, without
reading any Rust.

> **PROVISIONAL.** These vectors are generated from this repo's reference
> implementation. The canonical signing-string layout is not yet reconciled
> against deployed `rust-pois` (see [`../SESAME.md`](../SESAME.md) §8). Treat them
> as the scaffold's proposal, not a published standard.

## Files

- `signing.json`, tier 1: canonical signing string + HMAC-SHA256.
- `gcm.json`, tier 3: AES-256-GCM ciphertext + tag, with the bound AAD.

## How to use them (any language)

### `signing.json`

For each vector:

1. Decode `key_hex` and `nonce_hex` from hex; take `body_utf8` as UTF-8 bytes.
2. Build the canonical signing string per [`../SESAME.md`](../SESAME.md) §3.1 from
   `version`, `method`, `target`, `key_id`, `timestamp`, the base64 nonce,
   `channel` (empty line if `null`), and the lowercase-hex SHA-256 of the body.
3. Assert it equals `expected_signing_string` **byte-for-byte** (LF separators,
   no trailing newline).
4. Compute `base64(HMAC-SHA256(key, signing_string))` and assert it equals
   `expected_signature_b64`.

### `gcm.json`

For each vector:

1. Decode `key_hex` (32 bytes) and `iv_hex` (12 bytes).
2. Build the AAD per §5.1 and assert it equals `aad_utf8`.
3. AES-256-GCM-encrypt `plaintext_utf8` with that key, IV, and AAD.
4. Assert the ciphertext (tag stripped) equals `expected_ciphertext_hex` and the
   16-byte tag equals `base64`-decoded `expected_tag_b64`.

## Regenerating (Rust)

The committed files are produced by the reference generator and guarded by
`tests/conformance.rs`, which re-derives them from the current code:

```sh
cargo run --features cli --bin sesame-gen-vectors -- --out test-vectors
cargo test  --features serde --test conformance
```

If you change the canonical string or the GCM binding, the conformance test
fails until you regenerate, by design, so the published contract only ever
changes deliberately.
