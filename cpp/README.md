# sesame (C++)

A native **C++17** implementation of SESAME (Secure ESAM Authentication and
Message Encryption), the proposed SCTE 130-9 security layer for the ESAM
interface. It is a sibling of the Rust crate in this repo and is proven against
the **same golden vectors** (`../test-vectors/`), so a C++ signer and a Rust (or
rust-pois) verifier interoperate byte-for-byte.

- **Three tiers over a Tier-0 baseline:** HMAC-SHA256 auth (1), channel-scoped
  authorization (2), AES-256-GCM payload encryption (3), plus signed responses.
- **Crypto backend:** OpenSSL 3.x (EVP), behind a thin seam
  ([`crypto.hpp`](include/sesame/crypto.hpp)) so an embedded target can swap in
  mbedTLS/BoringSSL without touching the protocol code.
- **No framework lock-in:** `verify_request` / `sign_response` take the request
  parts, parsed headers, body, and `now` (Unix seconds). The key directory
  (`KeyProvider`) and replay memory (`ReplayCache`) are injected.

See [`../SESAME.md`](../SESAME.md) for the byte-exact wire format (draft v0.5).

## Build

Requires CMake >= 3.16, a C++17 compiler, and OpenSSL 3.x dev headers
(`libssl-dev`).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

- `conformance` reproduces every golden vector in `../test-vectors/`
  byte-for-byte (the cross-implementation gate).
- `unit` runs known-answer tests (RFC 4231 HMAC, NIST SP 800-38D AES-256-GCM),
  a full sign/verify round-trip, and the negative matrix.
- `sign_request` is a runnable client example: `./build/sign_request [1|2|3]`.

CMake options: `SESAME_BUILD_TESTS` (default ON), `SESAME_BUILD_EXAMPLES`
(default ON), `SESAME_VECTORS_DIR` (defaults to `../test-vectors`).

## Quick start

Verify an inbound request (the POIS side):

```cpp
#include "sesame/sesame.hpp"
using namespace sesame;

StaticKeyProvider keys;
keys.with_signing_key("sas-east-01", /*hmac key bytes*/{...},
                      ChannelScope::list({"SportsFeed-East"}));
InMemoryReplayCache replay(300);

SesameHeaders headers = SesameHeaders::from_lookup(
    [&](const char* name) -> std::optional<std::string> { return lookup_header(name); });
RequestContext ctx{"POST", "/esam", std::nullopt};

auto r = verify_request(SesameConfig{}, keys, replay, ctx, headers, body,
                        now_unix_seconds(), Tier::One);
if (r.ok) {
    // r.value.plaintext is the ESAM XML; r.value.achieved_tier / key_id / scope_channel
} else {
    // error_code(r.error) / error_http_status(r.error)  (Appendix A.7)
}
```

Sign an outbound response (the POIS side):

```cpp
ResponseParams p;
p.signing_key_id = "pois-primary";
p.correlation = "ap-1:sigid-20260224-001";  // the acquisitionSignalID answered
p.tier = Tier::One;
auto resp = sign_response(SesameConfig{}, keys, p, xml, now_unix_seconds());
// attach resp.value.headers, send resp.value.body with resp.value.content_type
```

## Layout

```
include/sesame/   public headers (hex, crypto, canonical, tier1, tier3,
                  message, keys, replay, protocol, sesame.hpp umbrella)
src/              OpenSSL crypto impl + tier1/tier3/message/protocol
tests/            conformance.cpp (golden vectors), unit.cpp (KATs + matrix)
examples/         sign_request.cpp
third_party/      vendored nlohmann/json single header (tests only, MIT)
```

## License

Dual-licensed under [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE), the
same as the rest of the repository. The vendored `third_party/json.hpp`
(nlohmann/json) is MIT and used only by the test harness.
