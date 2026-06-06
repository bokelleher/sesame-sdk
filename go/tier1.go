package sesame

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// rfc3339Z is the SESAME wire timestamp form: RFC-3339 UTC with a literal Z.
const rfc3339Z = "2006-01-02T15:04:05Z"

// Sign returns the lowercase-hex HMAC-SHA256 of canonical under key.
func Sign(key []byte, canonical string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a provided lowercase-hex signature in constant time.
func Verify(key []byte, canonical, providedHex string) bool {
	provided, err := hex.DecodeString(providedHex)
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	return hmac.Equal(mac.Sum(nil), provided)
}

// VerifyAny verifies against any candidate key (rotation overlap window).
func VerifyAny(keys [][]byte, canonical, providedHex string) bool {
	ok := false
	for _, k := range keys {
		if Verify(k, canonical, providedHex) {
			ok = true // no early-out
		}
	}
	return ok
}

// ParseRFC3339UTC parses YYYY-MM-DDTHH:MM:SSZ to Unix seconds.
func ParseRFC3339UTC(iso string) (int64, error) {
	t, err := time.Parse(rfc3339Z, iso)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// CheckFreshness reports whether timestampISO is within +/- windowSecs of nowUnix.
func CheckFreshness(timestampISO string, nowUnix, windowSecs int64) bool {
	ts, err := ParseRFC3339UTC(timestampISO)
	if err != nil {
		return false
	}
	d := nowUnix - ts
	if d < 0 {
		d = -d
	}
	return d <= windowSecs
}
