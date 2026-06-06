package sesame

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// BodyHashHex returns the lowercase-hex SHA-256 of the (possibly-encrypted) body.
func BodyHashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// RequestCanonical builds the Tier 1 request canonical string:
// method LF path LF timestamp LF nonce LF body-hash [LF scope].
// scope is nil unless Tier 2 is active.
func RequestCanonical(method, path, timestamp, nonce, bodyHashHex string, scope *string) string {
	fields := []string{method, path, timestamp, nonce, bodyHashHex}
	if scope != nil {
		fields = append(fields, *scope)
	}
	return strings.Join(fields, "\n")
}

// ResponseCanonical builds the response canonical string:
// "RESPONSE" LF correlation LF timestamp LF nonce LF body-hash [LF scope].
func ResponseCanonical(correlation, timestamp, nonce, bodyHashHex string, scope *string) string {
	fields := []string{"RESPONSE", correlation, timestamp, nonce, bodyHashHex}
	if scope != nil {
		fields = append(fields, *scope)
	}
	return strings.Join(fields, "\n")
}
