# sesame-esam (Python)

A native **Python** implementation of SESAME (Secure ESAM Authentication and
Message Encryption), the proposed SCTE 130-9 security layer for the ESAM
interface. A sibling of the Rust crate and C++ SDK in this repo, proven against
the **same golden vectors** (`../test-vectors/`), so a Python signer and a Rust,
C++, or rust-pois verifier interoperate byte-for-byte.

- **Three tiers over a Tier-0 baseline:** HMAC-SHA256 auth (1), channel-scoped
  authorization (2), AES-256-GCM payload encryption (3), plus signed responses.
- **One dependency:** [`cryptography`](https://pypi.org/project/cryptography/)
  for AES-256-GCM (`hmac`/`hashlib` from the stdlib cover the rest).
- **Pythonic API:** `verify_request` / `sign_response`; failures raise
  `SesameError` (with `.code` and `.http_status`, Appendix A.7).

PyPI package: `sesame-esam`; import name: `sesame`. See
[`../SESAME.md`](../SESAME.md) for the byte-exact wire format (draft v0.5).

## Install

```sh
pip install sesame-esam
```

## Quick start

Verify an inbound request (the POIS side):

```python
from sesame import (verify_request, RequestContext, SesameConfig, SesameHeaders,
                    StaticKeyProvider, ChannelScope, InMemoryReplayCache, Tier, SesameError)
import time

keys = StaticKeyProvider().with_signing_key(
    "sas-east-01", b"shared-secret", ChannelScope.list(["SportsFeed-East"]))
replay = InMemoryReplayCache(300)

headers = SesameHeaders.from_lookup(lambda name: request_headers.get(name))
ctx = RequestContext("POST", "/esam", target_channel=None)
try:
    v = verify_request(SesameConfig(), keys, replay, ctx, headers, body,
                       int(time.time()), Tier.ONE)
    # v.plaintext is the ESAM XML; v.achieved_tier / v.key_id / v.scope_channel
except SesameError as e:
    # e.code (SesameErrorCode), e.http_status
    ...
```

Sign an outbound response (the POIS side):

```python
from sesame import sign_response, ResponseParams, SesameConfig, Tier
import time

params = ResponseParams(signing_key_id="pois-primary",
                        correlation="ap-1:sigid-20260224-001", tier=Tier.ONE)
resp = sign_response(SesameConfig(), keys, params, xml, int(time.time()))
# attach resp.headers (list of (name, value)), send resp.body with resp.content_type
```

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # conformance (golden vectors) + unit (KATs + negative matrix)
python examples/sign_request.py 3
```

## License

Dual-licensed under [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE).
