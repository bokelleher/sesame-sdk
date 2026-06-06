# sesame (Go)

A native **Go** implementation of SESAME (Secure ESAM Authentication and
Message Encryption), the proposed SCTE 130-9 security layer for the ESAM
interface. A sibling of the Rust crate, C++ SDK, and Python SDK in this repo,
proven against the **same golden vectors** (`../test-vectors/`), so a Go signer
and a verifier in any of the four interoperate byte-for-byte.

- **Zero external dependencies.** The entire crypto set comes from the Go
  standard library (`crypto/hmac`, `crypto/sha256`, `crypto/aes`,
  `crypto/cipher`).
- **Three tiers over a Tier-0 baseline:** HMAC-SHA256 auth (1), channel-scoped
  authorization (2), AES-256-GCM payload encryption (3), plus signed responses.
- **Idiomatic API:** `VerifyRequest` / `SignResponse` return errors; failures
  are the sentinel `*SesameError` values (comparable with `errors.Is`, each with
  a `.Code` and `.HTTPStatus()`, Appendix A.7).

See [`../SESAME.md`](../SESAME.md) for the byte-exact wire format (draft v0.5).

## Install

```sh
go get github.com/bokelleher/sesame-sdk/go@latest
```

```go
import sesame "github.com/bokelleher/sesame-sdk/go"
```

## Quick start

Verify an inbound request (the POIS side):

```go
keys := sesame.NewStaticKeyProvider().
    WithSigningKey("sas-east-01", hmacKey, sesame.ListChannels("SportsFeed-East"))
replay := sesame.NewInMemoryReplayCache(300)

headers := sesame.HeadersFromLookup(func(name string) string { return req.Header.Get(name) })
ctx := sesame.RequestContext{Method: "POST", Path: "/esam"}

v, err := sesame.VerifyRequest(sesame.DefaultConfig(), keys, replay, ctx, headers, body,
    time.Now().Unix(), sesame.Tier1)
if err != nil {
    var se *sesame.SesameError
    errors.As(err, &se) // se.Code, se.HTTPStatus()
    return
}
// v.Plaintext is the ESAM XML; v.AchievedTier / v.KeyID / v.ScopeChannel
```

Sign an outbound response (the POIS side):

```go
resp, err := sesame.SignResponse(sesame.DefaultConfig(), keys, sesame.ResponseParams{
    SigningKeyID: "pois-primary",
    Correlation:  "ap-1:sigid-20260224-001", // the acquisitionSignalID answered
    Tier:         sesame.Tier1,
}, xml, time.Now().Unix())
// attach resp.Headers, send resp.Body with resp.ContentType
```

## Development

```sh
go vet ./...
go test ./...                 # conformance (golden vectors) + unit (KATs + matrix)
go run ./examples/sign_request 3
```

## License

Dual-licensed under [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE).
