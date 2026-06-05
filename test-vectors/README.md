# SESAME conformance vectors (golden)

These JSON files are the authoritative cross-implementation contract for SESAME.
They are **generated from the deployed `rust-pois` implementation** (via
[`../tools/golden-extractor`](../tools/golden-extractor/)), not from this crate,
so reproducing them proves a real second implementation matches the deployed wire
format rather than agreeing with itself.

`tests/conformance.rs` reconstructs each input and asserts this crate reproduces
every `expected_*` value byte-for-byte.

## Files

- `tier1.json`, `request_vectors` (Tier 1/2 canonical string + hex HMAC, plus a
  Tier-3 encrypt-then-MAC request whose body is `ciphertext‖tag`) and
  `response_vectors` (the `RESPONSE`/correlation canonical + signature).
- `tier3.json`, `aead_vectors`: AES-256-GCM AAD plus `ciphertext‖tag`.

## How to use them (any language)

### `tier1.json`

For each vector: hex-decode `body_hex`; compute lowercase-hex SHA-256 of it;
build the canonical string per [`../SESAME.md`](../SESAME.md) (5 LF-joined fields
for a request, with `scope` appended as a 6th line when non-null; the
`RESPONSE`/correlation form for responses); assert it equals
`expected_canonical`; then assert `lowercase-hex HMAC-SHA256(signing_key, canonical)`
equals `expected_signature_hex`.

### `tier3.json`

For each vector: hex-decode `enc_key_hex` (32 bytes) and `iv_hex` (12 bytes);
build the AAD (`version⏎key_id⏎timestamp⏎nonce[⏎scope]`) and assert it equals
`expected_aad_utf8`; AES-256-GCM-seal `plaintext_hex` and assert the
`ciphertext‖tag` equals `expected_body_hex`.

## Regenerating

Only when `rust-pois` changes the wire format. See
[`../tools/golden-extractor/README.md`](../tools/golden-extractor/README.md). The
vectors are a fixed contract and are not regenerated in CI; the conformance test
fails if the crate stops reproducing them.
