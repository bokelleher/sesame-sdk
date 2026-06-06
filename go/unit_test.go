package sesame

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func dec(s string) []byte { b, _ := hex.DecodeString(s); return b }

func TestSHA256Empty(t *testing.T) {
	if got := BodyHashHex(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("sha256 empty: %s", got)
	}
}

func TestRFC4231HMAC(t *testing.T) {
	got := Sign([]byte("Jefe"), "what do ya want for nothing?")
	if got != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" {
		t.Fatalf("rfc4231: %s", got)
	}
}

func TestNISTGCM(t *testing.T) {
	key := dec("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	iv := dec("cafebabefacedbaddecaf888")
	pt := dec("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
		"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	aad := dec("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	expected := dec("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
		"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
		"76fc6ece0f4e1768cddf8853bb2d551b")
	out, err := Seal(key, iv, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, expected) {
		t.Fatal("nist gcm ciphertext||tag mismatch")
	}
}

func TestFreshness(t *testing.T) {
	now, _ := ParseRFC3339UTC("2026-02-24T18:05:00Z")
	if !CheckFreshness("2026-02-24T18:00:00Z", now, 300) {
		t.Error("edge should be fresh")
	}
	if CheckFreshness("2026-02-24T17:59:59Z", now, 300) {
		t.Error("past edge should be stale")
	}
	if CheckFreshness("not-a-date", now, 300) {
		t.Error("unparseable should be false")
	}
}

var xml = []byte(`<?xml version="1.0"?><SignalProcessingEvent/>`)

func provider() *StaticKeyProvider {
	return NewStaticKeyProvider().
		WithSigningKey("sas-east-01", []byte("client-secret"), ListChannels("SportsFeed-East")).
		WithSigningKey("pois-primary", []byte("pois-secret"), AllChannels()).
		WithAEADKey("enc-sportsfeed-2026q1", bytes.Repeat([]byte{0x42}, 32))
}

func nowT(t *testing.T) int64 {
	n, err := ParseRFC3339UTC("2026-02-24T18:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func ctxT() RequestContext {
	ch := "SportsFeed-East"
	return RequestContext{Method: "POST", Path: "/esam?channel=SportsFeed-East", TargetChannel: &ch}
}

func makeRequest(t *testing.T, tier Tier, p *StaticKeyProvider) (Headers, []byte) {
	ts := "2026-02-24T18:00:00Z"
	nonce := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	var scope *string
	if tier >= Tier2 {
		s := "channel=SportsFeed-East"
		scope = &s
	}
	h := Headers{Version: ProtocolVersion, KeyID: "sas-east-01", Timestamp: ts, Nonce: nonce}
	if scope != nil {
		h.Scope = *scope
	}
	var body []byte
	if tier >= Tier3 {
		aead, _ := p.AEADKey("enc-sportsfeed-2026q1")
		iv := make([]byte, 12)
		aad := AADForHeaders(ProtocolVersion, "sas-east-01", ts, nonce, scope)
		sealed, err := Seal(aead, iv, aad, xml)
		if err != nil {
			t.Fatal(err)
		}
		body = sealed
		h.Encrypted = true
		h.EncKeyID = "enc-sportsfeed-2026q1"
		h.IV = hex.EncodeToString(iv)
	} else {
		body = xml
	}
	canon := RequestCanonical("POST", "/esam?channel=SportsFeed-East", ts, nonce, BodyHashHex(body), scope)
	key, _ := p.PrimarySigningKey("sas-east-01")
	h.Signature = Sign(key, canon)
	return h, body
}

func TestRoundtrip(t *testing.T) {
	for _, tier := range []Tier{Tier1, Tier2, Tier3} {
		p := provider()
		h, body := makeRequest(t, tier, p)
		v, err := VerifyRequest(DefaultConfig(), p, NewInMemoryReplayCache(300), ctxT(), h, body, nowT(t), tier)
		if err != nil {
			t.Fatalf("tier %d: %v", tier, err)
		}
		if !bytes.Equal(v.Plaintext, xml) {
			t.Errorf("tier %d plaintext", tier)
		}
		if v.AchievedTier != tier {
			t.Errorf("tier %d achieved %d", tier, v.AchievedTier)
		}
	}
}

func expectErr(t *testing.T, want, err error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("want %v, got %v", want, err)
	}
}

func TestNegativeMatrix(t *testing.T) {
	// tampered body
	p := provider()
	h, body := makeRequest(t, Tier1, p)
	_, err := VerifyRequest(DefaultConfig(), p, NewInMemoryReplayCache(300), ctxT(), h, append(body, 'X'), nowT(t), Tier1)
	expectErr(t, ErrSignatureMismatch, err)

	// replay
	p = provider()
	h, body = makeRequest(t, Tier1, p)
	cache := NewInMemoryReplayCache(300)
	if _, err := VerifyRequest(DefaultConfig(), p, cache, ctxT(), h, body, nowT(t), Tier1); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRequest(DefaultConfig(), p, cache, ctxT(), h, body, nowT(t), Tier1)
	expectErr(t, ErrReplayDetected, err)

	// stale
	p = provider()
	h, body = makeRequest(t, Tier1, p)
	_, err = VerifyRequest(DefaultConfig(), p, NewInMemoryReplayCache(300), ctxT(), h, body, nowT(t)+600, Tier1)
	expectErr(t, ErrExpiredTimestamp, err)

	// unknown key
	p = provider()
	h, body = makeRequest(t, Tier1, p)
	h.KeyID = "ghost"
	_, err = VerifyRequest(DefaultConfig(), p, NewInMemoryReplayCache(300), ctxT(), h, body, nowT(t), Tier1)
	expectErr(t, ErrUnknownKey, err)

	// wrong version
	p = provider()
	h, body = makeRequest(t, Tier1, p)
	h.Version = "2.0"
	_, err = VerifyRequest(DefaultConfig(), p, NewInMemoryReplayCache(300), ctxT(), h, body, nowT(t), Tier1)
	expectErr(t, ErrInvalidVersion, err)

	// truncated GCM tag (body hash changes -> signature mismatch first)
	p = provider()
	h, body = makeRequest(t, Tier3, p)
	_, err = VerifyRequest(DefaultConfig(), p, NewInMemoryReplayCache(300), ctxT(), h, body[:len(body)-1], nowT(t), Tier3)
	expectErr(t, ErrSignatureMismatch, err)
}

func TestSignResponseAndForgedDetection(t *testing.T) {
	p := provider()
	scope := "channel=SportsFeed-East"
	params := ResponseParams{
		SigningKeyID: "pois-primary",
		Correlation:  "ap-1:sig-001",
		Scope:        &scope,
		Tier:         Tier2,
	}
	r, err := SignResponse(DefaultConfig(), p, params, xml, nowT(t))
	if err != nil {
		t.Fatal(err)
	}
	get := func(name string) string {
		for _, kv := range r.Headers {
			if kv[0] == name {
				return kv[1]
			}
		}
		return ""
	}
	canon := ResponseCanonical("ap-1:sig-001", get(HeaderTimestamp), get(HeaderNonce), BodyHashHex(r.Body), &scope)
	key, _ := p.PrimarySigningKey("pois-primary")
	if !Verify(key, canon, get(HeaderSignature)) {
		t.Error("response should verify")
	}
	forged := ResponseCanonical("ap-1:sig-001", get(HeaderTimestamp), get(HeaderNonce), BodyHashHex([]byte("<blackout/>")), &scope)
	if Verify(key, forged, get(HeaderSignature)) {
		t.Error("forged response should fail")
	}
}
