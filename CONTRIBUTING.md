# Contributing to SESAME

SESAME is a wire-format standard with several implementations. The most
important thing to understand before contributing is:

## The test vectors are the contract

[`test-vectors/tier1.json`](test-vectors/) and
[`test-vectors/tier3.json`](test-vectors/) are the **language-neutral
conformance contract**. They are generated from the deployed `rust-pois`
reference implementation and pin the exact bytes SESAME puts on the wire:
canonical signing strings, HMAC-SHA256 signatures, GCM associated data, and
`ciphertext||tag`.

**An implementation is conformant if, and only if, it reproduces every
`expected_*` value in those files byte-for-byte.** Nothing else, not passing
its own tests, not "looking right", makes it conformant. Every SDK in this repo
proves exactly this, in CI:

| Language | Conformance test |
|---|---|
| Rust | `cargo test --features serde` (`tests/conformance.rs`) |
| C++ | `ctest` (`cpp/tests/conformance.cpp`) |
| Python | `pytest python/tests` (`test_conformance.py`) |
| Go | `go test ./...` (`go/conformance_test.go`) |

See [`test-vectors/README.md`](test-vectors/README.md) for how to consume the
vectors from any language, and [`SESAME.md`](SESAME.md) for the byte-exact wire
format (draft v0.5).

## Adding a new language implementation

You do not need permission, the vectors are public and the format is specified.
The recommended path:

1. Read [`SESAME.md`](SESAME.md).
2. Implement the wire primitives: the canonical strings, HMAC-SHA256 (lowercase
   hex), AES-256-GCM (`ciphertext||tag`), the AAD, and RFC-3339 freshness.
3. Write a conformance harness that loads `test-vectors/*.json` and asserts your
   implementation reproduces every `expected_*` value.
4. Layer the high-level `verify_request` / `sign_response` on top, mirroring the
   existing SDKs (Tier 0-3, the `KeyProvider` and `ReplayCache` seams, the
   Appendix A.7 error taxonomy).
5. If contributing it back here, add it under its own top-level directory with a
   CI job that runs the conformance harness, and exclude it from the Rust crate
   package (`Cargo.toml` `exclude`).

## Changing the wire format

The vectors are **not** hand-edited. They are regenerated from `rust-pois` (the
source of truth) when the deployed wire format changes, via
[`tools/golden-extractor`](tools/golden-extractor/). A wire-format change is a
deliberate, reviewed event: regenerate the vectors, then every SDK's conformance
test tells you whether it still matches. Never tweak a vector to make a test
pass.

## Conventions

- Each SDK keeps its own toolchain conventions (rustfmt/clippy, clang-format-ish
  + `-Werror`, gofmt/vet, etc.); CI enforces them.
- Dual-licensed **MIT OR Apache-2.0**. Contributions are accepted under the same
  terms.
- Commit messages: imperative subject; keep changes scoped to one concern.
