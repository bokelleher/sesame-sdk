package sesame

import "strings"

// SESAME header names (Appendix A.6).
const (
	HeaderVersion   = "X-SESAME-Version"
	HeaderKeyID     = "X-SESAME-KeyId"
	HeaderTimestamp = "X-SESAME-Timestamp"
	HeaderNonce     = "X-SESAME-Nonce"
	HeaderSignature = "X-SESAME-Signature"
	HeaderScope     = "X-SESAME-Scope"
	HeaderEncrypted = "X-SESAME-Encrypted"
	HeaderEncKeyID  = "X-SESAME-EncKeyId"
	HeaderIV        = "X-SESAME-IV"
)

// ProtocolVersion is the X-SESAME-Version value this implementation speaks.
const ProtocolVersion = "1.0"

// SesameError is a fail-closed verification/signing failure (Appendix A.7).
type SesameError struct {
	Code string
}

func (e *SesameError) Error() string { return e.Code }

// HTTPStatus returns the HTTP status for this error (Appendix A.7).
func (e *SesameError) HTTPStatus() int {
	switch e.Code {
	case ErrInvalidVersion.Code, ErrDecryptFailed.Code:
		return 400
	case ErrScopeDenied.Code:
		return 403
	default:
		return 401
	}
}

// Sentinel errors, comparable with errors.Is.
var (
	ErrMissingHeaders    = &SesameError{"sesame_missing_headers"}
	ErrInvalidVersion    = &SesameError{"sesame_invalid_version"}
	ErrUnknownKey        = &SesameError{"sesame_unknown_key"}
	ErrExpiredTimestamp  = &SesameError{"sesame_expired_timestamp"}
	ErrReplayDetected    = &SesameError{"sesame_replay_detected"}
	ErrSignatureMismatch = &SesameError{"sesame_signature_mismatch"}
	ErrScopeDenied       = &SesameError{"sesame_scope_denied"}
	ErrDecryptFailed     = &SesameError{"sesame_decrypt_failed"}
	ErrKeyRevoked        = &SesameError{"sesame_key_revoked"}
)

// Headers is the parsed SESAME header view. An empty string means absent.
type Headers struct {
	Version   string
	KeyID     string
	Timestamp string
	Nonce     string
	Signature string
	Scope     string
	Encrypted bool
	EncKeyID  string
	IV        string
}

// IsAbsent reports whether no Tier-1 headers are present (Tier 0).
func (h Headers) IsAbsent() bool {
	return h.Version == "" && h.KeyID == "" && h.Timestamp == "" &&
		h.Nonce == "" && h.Signature == ""
}

// HeadersFromLookup parses headers from a case-insensitive name->value getter
// that returns "" for an absent header.
func HeadersFromLookup(get func(string) string) Headers {
	return Headers{
		Version:   get(HeaderVersion),
		KeyID:     get(HeaderKeyID),
		Timestamp: get(HeaderTimestamp),
		Nonce:     get(HeaderNonce),
		Signature: get(HeaderSignature),
		Scope:     get(HeaderScope),
		Encrypted: strings.EqualFold(get(HeaderEncrypted), "true"),
		EncKeyID:  get(HeaderEncKeyID),
		IV:        get(HeaderIV),
	}
}
