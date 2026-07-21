# SESAME Wire Format

This document specifies, byte-for-byte, the SESAME (Secure ESAM Authentication
and Message Encryption) protocol implemented by the `sesame` crate. It mirrors
**ANSI/SCTE 130-9 (SESAME) draft v0.5** and matches the deployed `rust-pois`
reference implementation from which this crate was extracted. The golden vectors
in [`test-vectors/`](test-vectors/) are the executable form of this document.

SESAME adds nothing to the ESAM XML. Tiers 1 and 2 leave the body untouched;
Tier 3 replaces the body with ciphertext. No SCTE 130-2/-5/-7/-8 schema changes.

Earlier drafts left several points underspecified (scope binding, the response
canonical form, the GCM AAD, IV uniqueness, encrypt-then-MAC ordering). Draft
v0.5 ratifies all of them with normative `SHALL` language; this document and the
crate follow v0.5.

## Tiers

| Tier | Capability | Mechanism |
|---|---|---|
| 0 | Unauthenticated baseline | no SESAME headers (backward compatible) |
| 1 | Authentication + integrity | HMAC-SHA256 over a canonical string |
| 2 | Channel-scoped authorization | signed `X-SESAME-Scope`, policy lookup |
| 3 | Payload encryption | AES-256-GCM (96-bit IV, 128-bit tag) |

Tiers are additive and independently enableable. A channel's minimum required
tier is host policy; there is no on-wire tier-advertisement header.

## Headers

| Header | Tier | Value |
|---|---|---|
| `X-SESAME-Version` | 1+ | `1.0` |
| `X-SESAME-KeyId` | 1+ | signing credential id |
| `X-SESAME-Timestamp` | 1+ | ISO-8601 UTC, e.g. `2026-02-24T18:00:00Z` |
| `X-SESAME-Nonce` | 1+ | 128-bit random, lowercase hex (32 chars) |
| `X-SESAME-Signature` | 1+ | HMAC-SHA256, lowercase hex (64 chars) |
| `X-SESAME-Scope` | 2+ | `channel=<id>` |
| `X-SESAME-Encrypted` | 3 | `true` |
| `X-SESAME-EncKeyId` | 3 | encryption credential id (separate namespace) |
| `X-SESAME-IV` | 3 | 96-bit GCM IV, lowercase hex (24 chars) |

Header names are matched case-insensitively. All binary fields (nonce,
signature, IV) are lowercase hex. Tier 3 sets `Content-Type:
application/octet-stream`; the original `application/xml` type is not preserved
on the wire.

## Tier 1: canonical signing string

The HMAC-SHA256 signature covers this exact string (newline = `\n` = `0x0A`,
no trailing newline):

```
<HTTP-METHOD>\n
<request-target>\n          ; path + query, exactly as sent, e.g. /esam?channel=SportsFeed-East
<X-SESAME-Timestamp>\n
<X-SESAME-Nonce>\n
<lowercase-hex SHA-256 of the body AS TRANSMITTED>
```

The body hash is over the transmitted body. With Tier 3 active the transmitted
body is the ciphertext including the appended tag, so the scheme is
encrypt-then-MAC. There is no version-prefix line and no key-id line.

### Tier 2 scope binding

When `X-SESAME-Scope` is present, its exact value is appended as a sixth line:

```
<method>\n<target>\n<timestamp>\n<nonce>\n<body-hash>\n<scope-value>
```

so a request signed for one channel cannot be replayed against another.

### Signature

```
signature = lowercase-hex( HMAC-SHA256( key, canonical-string ) )
```

The verifier recomputes the canonical string and compares in constant time. Key
rotation is supported: during an overlap window a key-id may have multiple valid
keys, and verification accepts any of them.

## Tier 1: response signing

A SESAME server signs every response to an authenticated request, with its own
credential and a freshly generated nonce. Because a response carries no method or
request-target, the response canonical string is:

```
RESPONSE\n
<correlation>\n             ; the acquisitionSignalID being answered
<X-SESAME-Timestamp>\n
<X-SESAME-Nonce>\n
<body-hash>
[ \n<scope-value> ]         ; present iff Tier 2+
```

`correlation` binds the signed response to the specific request signal it
answers, defeating response substitution. This is the highest-value protection:
a forged or tampered conditioning decision (spoofed blackout, avail, or redirect)
fails verification. A client SHALL verify the response signature, timestamp
freshness, and correlation.

## Tier 3: AES-256-GCM

- Body = `AES-256-GCM(key, IV, AAD, plaintext)` = `ciphertext || 128-bit tag`.
- **IV**: a fresh 96-bit value from a CSPRNG per message, never reused with a
  key. A request and its response use independent IVs even under the same
  `EncKeyId`.
- **AAD**: the SESAME header set, newline-joined, binding the ciphertext to its
  headers:
  ```
  <X-SESAME-Version>\n<X-SESAME-KeyId>\n<X-SESAME-Timestamp>\n<X-SESAME-Nonce>[\n<scope-value>]
  ```
- Encryption keys live in a namespace separate from signing keys
  (`X-SESAME-EncKeyId` vs `X-SESAME-KeyId`) and rotate independently.

## Order of operations (all tiers)

**Send:** serialize XML, Tier 3 encrypt (AAD = headers), Tier 1 SHA-256 over the
ciphertext, build canonical, HMAC, attach headers, send.

**Receive:** Tier 1 verify (version, freshness, signature), replay check, Tier 2
authorize, Tier 3 decrypt, parse XML. Fail closed at each step.

## Replay protection

- Reject timestamps outside `±replay_window_secs` (default 300 s).
- Reject any `(KeyId, Nonce)` already seen within the window.
- Replay is checked after signature validation, so unauthenticated traffic
  cannot poison the cache.
- The reference cache is in-memory and per-process. Horizontally scaled
  deployments back the `ReplayCache` trait with a shared store.

### What the window is for

The window is not an interval in which replay succeeds. A request replayed
inside it presents a `(KeyId, Nonce)` the server has already recorded and is
refused by the cache; one replayed outside it fails the freshness check. The two
checks are complementary and leave no gap between them. The window's function is
to bound cache residency: an entry need only be retained while a timestamp could
still be considered fresh, so live entries are at most (window × request rate).

### Clock discipline

The window MUST exceed the worst-case clock offset between a signing client and
the verifying server, since a larger offset rejects legitimate traffic.
Deployments SHOULD discipline both ends against a common time source. NTP is
sufficient at this scale, and broadcast facilities typically already distribute
PTP or GPS time for unrelated reasons.

`sesame_expired_timestamp` is deliberately distinct from
`sesame_signature_mismatch` so operators can alarm on the former: a rising rate
of timestamp rejections indicates clock drift, not attack.

A server whose own clock is undisciplined fails closed and rejects all traffic.
That is the correct direction, but it makes the server's time source an
availability dependency that deployment planning must account for.

### Cache maintenance

Expiring entries is where an otherwise correct implementation can still miss the
latency budget. A cache that sweeps expired entries on every lookup costs O(n)
per request, where n is (window × request rate); under a shared lock this also
makes throughput fall as concurrency rises rather than scale with it.
Implementations SHOULD amortize expiry, for example by sweeping at most once per
wall-clock second, so that per-request cost is O(1).

Retaining an already-expired entry slightly longer is safe: a stale entry can
only cause a rejection, never a false acceptance. The cost of amortizing is that
the memory bound becomes (window + sweep interval) × request rate.

### Cache loss

Replay protection holds only while the cache holds. A restart that discards an
in-memory cache reopens replay for the remainder of the window, and nodes that
do not share a cache allow a request accepted by one to be replayed against
another. Deployments that require strict replay protection across restarts or
across nodes MUST back the `ReplayCache` seam with a shared store.

## Error codes

Distinct fail-closed errors map to wire codes and HTTP status (Appendix A.7):
`sesame_missing_headers`, `sesame_invalid_version` (400), `sesame_unknown_key`,
`sesame_expired_timestamp`, `sesame_replay_detected`, `sesame_signature_mismatch`,
`sesame_scope_denied` (403), `sesame_decrypt_failed` (400), `sesame_key_revoked`.
All 401 unless noted. A host that wants to avoid the mild key-enumeration signal
of distinct 401 codes can collapse them to a single opaque 401.

## Key configuration

Key distribution is out of band and is a host responsibility. The crate exposes
a `KeyProvider` trait (signing keys with rotation, separate AEAD keys, channel
authorization, revocation) and ships a static, config-backed reference impl.
