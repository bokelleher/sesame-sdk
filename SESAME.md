# SESAME, Security Extensions for the ESAM interface

> **Status: DRAFT / PROVISIONAL.** This document describes the wire format as
> implemented by the `sesame` reference crate in this repository. The canonical
> signing string and the GCM associated-data construction are **not yet
> reconciled** against the deployed `rust-pois` implementation. Per the handoff
> (§3), the authoritative extraction MOVES the deployed logic byte-for-byte; if
> the deployment differs, this document and the conformance vectors change to
> match it. Do not cite this as a published standard until that reconciliation
> happens.
>
> Specification text license: see [`LICENSE-SPEC`](LICENSE-SPEC) (provisionally
> CC0-1.0). Code license: Apache-2.0.

## 1. Overview

SESAME is the proposed SCTE 130-9 security layer for the ESAM interface. It
secures the two-party HTTP exchange between an ESAM client (encoder, packager,
ADS) and an ESAM server (POIS) using **three additive tiers**, all carried in
**HTTP headers** with **no change to any ESAM XML schema**:

| Tier | Property | Mechanism |
|------|----------|-----------|
| 1 | Authentication + integrity | HMAC-SHA256 over a canonical signing string |
| 2 | Authorization | Channel-scoped, enforced against the resolved key |
| 3 | Confidentiality | AES-256-GCM payload encryption |

The tiers are additive: a deployment may run tier 1 alone, tiers 1+2, or all
three. Tier 2 has no standalone existence, it constrains a tier 1 identity.
Tier 3 is always accompanied by tier 1 (the signature covers the ciphertext).

## 2. Headers

All header names are case-insensitive on receipt; the canonical spellings are:

| Header | Tier | Value |
|--------|------|-------|
| `X-Sesame-Version` | 1 | Protocol version. This document defines `1`. |
| `X-Sesame-Key-Id` | 1 | Opaque key identifier; resolves to a key (and scope). |
| `X-Sesame-Timestamp` | 1 | Unix time in seconds, decimal ASCII. |
| `X-Sesame-Nonce` | 1 | Anti-replay nonce, base64. RECOMMENDED ≥ 16 random bytes. |
| `X-Sesame-Channel` | 2 | Channel scope. Omitted when tier 2 is unused. |
| `X-Sesame-Signature` | 1 | base64 of the 32-byte HMAC-SHA256. |
| `X-Sesame-Encryption` | 3 | Suite name. This document defines `AES-256-GCM`. |
| `X-Sesame-IV` | 3 | base64 of the 12-byte GCM IV. |
| `X-Sesame-Tag` | 3 | base64 of the 16-byte GCM authentication tag. |

Encodings are fixed: base64 is the standard alphabet **with** padding (RFC 4648
§4); hex (where it appears, e.g. the body hash) is **lowercase**.

## 3. Tier 1, Authentication & integrity

### 3.1 Canonical signing string

The signer and verifier MUST construct the identical signing string, or the
HMAC will not match and the exchange fails. The string is exactly these nine
fields, each on its own line, joined by a single LF (`0x0A`), with **no trailing
newline**:

```
SESAME-HMAC-SHA256
<version>
<HTTP method, uppercased>
<request-target>
<key-id>
<timestamp, decimal seconds>
<nonce, base64>
<channel scope, or an empty line if tier 2 is unused>
<lowercase hex SHA-256 of the transmitted body>
```

- **request-target** is the path plus any query string, exactly as sent (e.g.
  `/esam/signal?ack=1`).
- The **transmitted body** is the bytes actually on the wire: under tier 3 this
  is the ciphertext, so the signature binds the encrypted payload.
- When tier 2 is not used, the channel field is an **empty line** (the LF is
  still present; the field is just empty).

### 3.2 Signature

```
signature = base64( HMAC-SHA256( key, utf8(signing_string) ) )
```

The verifier recomputes the signing string from the received headers, request
line, and body, recomputes the HMAC, and compares in **constant time**. The key
is obtained from `X-Sesame-Key-Id` via the deployment's key directory.

## 4. Tier 2, Authorization

When a request carries `X-Sesame-Channel`, the value is bound into the signing
string (so it cannot be altered without breaking the signature) and the verifier
additionally checks that the resolved key is **authorized for that channel**.
The authorization table (key → permitted channels) is deployment-specific; the
SDK exposes it as the `KeyResolver::channel_allowed` hook. A tier-1-only
deployment leaves the channel absent and the check trivially passes.

## 5. Tier 3, Confidentiality

The payload is encrypted with **AES-256-GCM** before signing, so tier 1 protects
the ciphertext. The 256-bit key is identified by the same `X-Sesame-Key-Id`
(deployments MAY use distinct keys for MAC vs. encryption behind one id); the
12-byte IV is unique per (key, message) and travels in `X-Sesame-IV`; the 16-byte
tag travels in `X-Sesame-Tag`. The ciphertext is the HTTP body.

### 5.1 Associated data

GCM additionally authenticates an associated-data (AAD) string built from fields
that tier 1 already covers, binding the ciphertext to the request context without
the circular dependency of feeding the whole signing string (which hashes the
ciphertext) back into the cipher:

```
SESAME-AAD
<key-id>
<timestamp, decimal seconds>
<nonce, base64>
<channel scope, or empty>
```

(four LF-joined fields, no trailing newline).

### 5.2 Order of operations

**Sender:** encrypt → set IV/Tag/Encryption headers → compute signing string over
the ciphertext → HMAC. **Receiver:** verify HMAC over the ciphertext → check
freshness and replay → GCM-decrypt with the same AAD.

## 6. Freshness & replay

Two independent checks, both performed *after* the signature verifies:

1. **Freshness.** Reject if `|now − timestamp|` exceeds the freshness window
   (default ±300 s). Future-dated requests are rejected symmetrically.
2. **Replay.** Within the window, a `(nonce)` MUST be accepted at most once. The
   replay memory is the deployment's responsibility (the SDK injects it as
   `NonceStore`); entries older than the window MAY be evicted because the
   freshness check rejects them first.

The split is deliberate: the freshness rule lives in the portable core, while
the replay *memory* lives in the host (in-memory for a node, distributed for a
cluster, a ring buffer for a device).

## 7. Conformance

The normative test cases are the language-neutral JSON in
[`test-vectors/`](test-vectors/). An implementation in any language is conformant
when it reproduces every `expected_*` value from the given inputs. See
[`test-vectors/README.md`](test-vectors/README.md).

## 8. Open items

- Reconcile §3.1 and §5.1 against deployed `rust-pois` (handoff §3, §10.1).
- Confirm spec-text license: CC0 vs CC-BY (handoff §10.3).
- Key rotation and multi-key-per-id semantics are out of scope here; they belong
  to a separate operational layer.
