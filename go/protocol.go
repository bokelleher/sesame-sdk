package sesame

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

// Tier is a SESAME security tier (additive: Tier N implies 1..N).
type Tier int

const (
	Tier0 Tier = 0
	Tier1 Tier = 1
	Tier2 Tier = 2
	Tier3 Tier = 3
)

// Config is the deployment-wide SESAME configuration.
type Config struct {
	ReplayWindowSecs int64
}

// DefaultConfig returns the default configuration (300s replay window).
func DefaultConfig() Config { return Config{ReplayWindowSecs: 300} }

// VerifiedRequest is the outcome of a successful VerifyRequest.
type VerifiedRequest struct {
	Plaintext    []byte
	KeyID        string
	ScopeChannel *string
	AchievedTier Tier
}

// RequestContext carries the request line a signature is bound to.
type RequestContext struct {
	Method        string
	Path          string // request-target (path + query) as signed
	TargetChannel *string
}

// SignedResponse is a signed (and optionally encrypted) outbound response.
type SignedResponse struct {
	Headers     [][2]string // (name, value)
	Body        []byte
	ContentType string
}

// ResponseParams configures SignResponse.
type ResponseParams struct {
	SigningKeyID string
	Correlation  string // acquisitionSignalID answered
	Scope        *string
	Tier         Tier
	EncKeyID     *string
}

// FormatRFC3339UTC formats Unix seconds as YYYY-MM-DDTHH:MM:SSZ.
func FormatRFC3339UTC(unixSecs int64) string {
	return time.Unix(unixSecs, 0).UTC().Format(rfc3339Z)
}

// ParseScopeChannel parses channel=<id> from an X-SESAME-Scope value.
func ParseScopeChannel(scope string) (string, bool) {
	const prefix = "channel="
	if !strings.HasPrefix(scope, prefix) {
		return "", false
	}
	return strings.TrimSpace(scope[len(prefix):]), true
}

// VerifyRequest verifies an inbound ESAM request, failing closed at each step
// with the matching sentinel SesameError (Appendix A.7).
func VerifyRequest(cfg Config, provider KeyProvider, replay ReplayCache, ctx RequestContext, headers Headers, rawBody []byte, nowUnix int64, minTier Tier) (*VerifiedRequest, error) {
	// Tier 0: unauthenticated passthrough, only when policy permits it.
	if headers.IsAbsent() {
		if minTier == Tier0 {
			return &VerifiedRequest{Plaintext: rawBody, AchievedTier: Tier0}, nil
		}
		return nil, ErrMissingHeaders
	}

	if headers.Version == "" || headers.KeyID == "" || headers.Timestamp == "" ||
		headers.Nonce == "" || headers.Signature == "" {
		return nil, ErrMissingHeaders
	}
	if headers.Version != ProtocolVersion {
		return nil, ErrInvalidVersion
	}
	if !CheckFreshness(headers.Timestamp, nowUnix, cfg.ReplayWindowSecs) {
		return nil, ErrExpiredTimestamp
	}
	if provider.IsRevoked(headers.KeyID) {
		return nil, ErrKeyRevoked
	}
	signingKeys := provider.SigningKeys(headers.KeyID)
	if len(signingKeys) == 0 {
		return nil, ErrUnknownKey
	}

	var scope *string
	if headers.Scope != "" {
		s := headers.Scope
		scope = &s
	}

	bodyHash := BodyHashHex(rawBody)
	canon := RequestCanonical(ctx.Method, ctx.Path, headers.Timestamp, headers.Nonce, bodyHash, scope)
	if !VerifyAny(signingKeys, canon, headers.Signature) {
		return nil, ErrSignatureMismatch
	}

	// Replay only after the signature is valid.
	if !replay.CheckAndRemember(headers.KeyID, headers.Nonce, nowUnix) {
		return nil, ErrReplayDetected
	}

	achieved := Tier1
	var scopeChannel *string

	if scope != nil {
		declared, ok := ParseScopeChannel(*scope)
		if !ok {
			return nil, ErrScopeDenied
		}
		if ctx.TargetChannel != nil && *ctx.TargetChannel != declared {
			return nil, ErrScopeDenied
		}
		if !provider.IsAuthorized(headers.KeyID, declared) {
			return nil, ErrScopeDenied
		}
		scopeChannel = &declared
		achieved = Tier2
	} else if minTier >= Tier2 {
		return nil, ErrScopeDenied
	}

	var plaintext []byte
	if headers.Encrypted {
		if headers.EncKeyID == "" || headers.IV == "" {
			return nil, ErrDecryptFailed
		}
		iv, err := hex.DecodeString(headers.IV)
		if err != nil || len(iv) != IVLen {
			return nil, ErrDecryptFailed
		}
		aead, ok := provider.AEADKey(headers.EncKeyID)
		if !ok {
			return nil, ErrDecryptFailed
		}
		aad := AADForHeaders(headers.Version, headers.KeyID, headers.Timestamp, headers.Nonce, scope)
		pt, err := Open(aead, iv, aad, rawBody)
		if err != nil {
			return nil, ErrDecryptFailed
		}
		plaintext = pt
		achieved = Tier3
	} else if minTier >= Tier3 {
		return nil, ErrDecryptFailed
	} else {
		plaintext = rawBody
	}

	if achieved < minTier {
		return nil, ErrMissingHeaders
	}

	return &VerifiedRequest{
		Plaintext:    plaintext,
		KeyID:        headers.KeyID,
		ScopeChannel: scopeChannel,
		AchievedTier: achieved,
	}, nil
}

// SignResponse signs (and optionally encrypts) an outbound ESAM response. A
// fresh nonce and (for Tier 3) IV are drawn from crypto/rand per call.
func SignResponse(cfg Config, provider KeyProvider, params ResponseParams, plaintextXML []byte, nowUnix int64) (*SignedResponse, error) {
	_ = cfg // reserved (window not needed when signing)
	signingKey, ok := provider.PrimarySigningKey(params.SigningKeyID)
	if !ok {
		return nil, ErrUnknownKey
	}

	timestamp := FormatRFC3339UTC(nowUnix)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)

	headers := [][2]string{
		{HeaderVersion, ProtocolVersion},
		{HeaderKeyID, params.SigningKeyID},
		{HeaderTimestamp, timestamp},
		{HeaderNonce, nonce},
	}
	if params.Scope != nil {
		headers = append(headers, [2]string{HeaderScope, *params.Scope})
	}

	var body []byte
	var contentType string
	if params.Tier >= Tier3 {
		if params.EncKeyID == nil {
			return nil, ErrDecryptFailed
		}
		aead, ok := provider.AEADKey(*params.EncKeyID)
		if !ok {
			return nil, ErrDecryptFailed
		}
		iv := make([]byte, IVLen)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
		aad := AADForHeaders(ProtocolVersion, params.SigningKeyID, timestamp, nonce, params.Scope)
		sealed, err := Seal(aead, iv, aad, plaintextXML)
		if err != nil {
			return nil, err
		}
		body = sealed
		headers = append(headers,
			[2]string{HeaderEncrypted, "true"},
			[2]string{HeaderEncKeyID, *params.EncKeyID},
			[2]string{HeaderIV, hex.EncodeToString(iv)},
		)
		contentType = "application/octet-stream"
	} else {
		body = plaintextXML
		contentType = "application/xml"
	}

	bodyHash := BodyHashHex(body)
	canon := ResponseCanonical(params.Correlation, timestamp, nonce, bodyHash, params.Scope)
	headers = append(headers, [2]string{HeaderSignature, Sign(signingKey, canon)})

	return &SignedResponse{Headers: headers, Body: body, ContentType: contentType}, nil
}
