package sesame

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These vectors are generated from the deployed rust-pois implementation and
// shared across the Rust/C++/Python/Go SDKs. Reproducing them byte-for-byte is
// what makes this a real implementation of SESAME, not a separate dialect.

type tier1File struct {
	RequestVectors  []requestVector  `json:"request_vectors"`
	ResponseVectors []responseVector `json:"response_vectors"`
}

type requestVector struct {
	Name              string  `json:"name"`
	Method            string  `json:"method"`
	Path              string  `json:"path"`
	Timestamp         string  `json:"timestamp"`
	Nonce             string  `json:"nonce"`
	Scope             *string `json:"scope"`
	SigningKeyHex     string  `json:"signing_key_hex"`
	BodyHex           string  `json:"body_hex"`
	ExpectedCanonical string  `json:"expected_canonical"`
	ExpectedSigHex    string  `json:"expected_signature_hex"`
}

type responseVector struct {
	Name              string  `json:"name"`
	Correlation       string  `json:"correlation"`
	Timestamp         string  `json:"timestamp"`
	Nonce             string  `json:"nonce"`
	Scope             *string `json:"scope"`
	SigningKeyHex     string  `json:"signing_key_hex"`
	BodyHex           string  `json:"body_hex"`
	ExpectedCanonical string  `json:"expected_canonical"`
	ExpectedSigHex    string  `json:"expected_signature_hex"`
}

type tier3File struct {
	AEADVectors []aeadVector `json:"aead_vectors"`
}

type aeadVector struct {
	Name            string  `json:"name"`
	EncKeyHex       string  `json:"enc_key_hex"`
	IVHex           string  `json:"iv_hex"`
	Version         string  `json:"version"`
	KeyID           string  `json:"key_id"`
	Timestamp       string  `json:"timestamp"`
	Nonce           string  `json:"nonce"`
	Scope           *string `json:"scope"`
	PlaintextHex    string  `json:"plaintext_hex"`
	ExpectedAADUTF8 string  `json:"expected_aad_utf8"`
	ExpectedBodyHex string  `json:"expected_body_hex"`
}

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "test-vectors", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestTier1RequestVectorsReproduce(t *testing.T) {
	var f tier1File
	loadVectors(t, "tier1.json", &f)
	if len(f.RequestVectors) == 0 {
		t.Fatal("no request vectors")
	}
	for _, v := range f.RequestVectors {
		body := mustHex(t, v.BodyHex)
		canon := RequestCanonical(v.Method, v.Path, v.Timestamp, v.Nonce, BodyHashHex(body), v.Scope)
		if canon != v.ExpectedCanonical {
			t.Errorf("%s: canonical mismatch\n got: %q\nwant: %q", v.Name, canon, v.ExpectedCanonical)
		}
		if sig := Sign(mustHex(t, v.SigningKeyHex), canon); sig != v.ExpectedSigHex {
			t.Errorf("%s: signature mismatch", v.Name)
		}
	}
}

func TestTier1ResponseVectorsReproduce(t *testing.T) {
	var f tier1File
	loadVectors(t, "tier1.json", &f)
	if len(f.ResponseVectors) == 0 {
		t.Fatal("no response vectors")
	}
	for _, v := range f.ResponseVectors {
		body := mustHex(t, v.BodyHex)
		canon := ResponseCanonical(v.Correlation, v.Timestamp, v.Nonce, BodyHashHex(body), v.Scope)
		if canon != v.ExpectedCanonical {
			t.Errorf("%s: canonical mismatch", v.Name)
		}
		if sig := Sign(mustHex(t, v.SigningKeyHex), canon); sig != v.ExpectedSigHex {
			t.Errorf("%s: signature mismatch", v.Name)
		}
	}
}

func TestTier3AEADVectorsReproduce(t *testing.T) {
	var f tier3File
	loadVectors(t, "tier3.json", &f)
	if len(f.AEADVectors) == 0 {
		t.Fatal("no aead vectors")
	}
	for _, v := range f.AEADVectors {
		aad := AADForHeaders(v.Version, v.KeyID, v.Timestamp, v.Nonce, v.Scope)
		if string(aad) != v.ExpectedAADUTF8 {
			t.Errorf("%s: aad mismatch", v.Name)
		}
		key := mustHex(t, v.EncKeyHex)
		iv := mustHex(t, v.IVHex)
		pt := mustHex(t, v.PlaintextHex)
		body, err := Seal(key, iv, aad, pt)
		if err != nil {
			t.Fatalf("%s: seal: %v", v.Name, err)
		}
		if got := hex.EncodeToString(body); got != v.ExpectedBodyHex {
			t.Errorf("%s: ciphertext||tag mismatch", v.Name)
		}
		rec, err := Open(key, iv, aad, body)
		if err != nil || string(rec) != string(pt) {
			t.Errorf("%s: decrypt round-trip failed", v.Name)
		}
	}
}
