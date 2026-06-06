// Command sign_request is a minimal SESAME client. It builds a signed (and
// optionally AES-256-GCM-encrypted) ESAM request with this SDK's primitives,
// then self-verifies it with VerifyRequest (the same oracle a server runs)
// before it would go on the wire.
//
// Run: go run ./examples/sign_request [1|2|3]   # tier, default 1
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	sesame "github.com/bokelleher/sesame-sdk/go"
)

func main() {
	tierN := 1
	if len(os.Args) > 1 {
		if n, err := strconv.Atoi(os.Args[1]); err == nil {
			tierN = n
		}
	}
	var tier sesame.Tier
	switch {
	case tierN >= 3:
		tier = sesame.Tier3
	case tierN == 2:
		tier = sesame.Tier2
	default:
		tier = sesame.Tier1
	}

	aeadKey := make([]byte, 32)
	for i := range aeadKey {
		aeadKey[i] = byte(i + 1)
	}
	p := sesame.NewStaticKeyProvider().
		WithSigningKey("sas-east-01", []byte("shared-secret"), sesame.ListChannels("SportsFeed-East")).
		WithAEADKey("enc-2026q1", aeadKey)

	xml := []byte(`<?xml version="1.0"?><SignalProcessingNotification/>`)
	path := "/esam?channel=SportsFeed-East"
	keyID := "sas-east-01"

	now := time.Now().Unix()
	ts := sesame.FormatRFC3339UTC(now)
	nonceBytes := make([]byte, 16)
	mustRand(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	var scope *string
	if tier >= sesame.Tier2 {
		s := "channel=SportsFeed-East"
		scope = &s
	}

	h := sesame.Headers{Version: sesame.ProtocolVersion, KeyID: keyID, Timestamp: ts, Nonce: nonce}
	if scope != nil {
		h.Scope = *scope
	}

	var body []byte
	if tier >= sesame.Tier3 {
		aead, _ := p.AEADKey("enc-2026q1")
		iv := make([]byte, 12)
		mustRand(iv)
		aad := sesame.AADForHeaders(sesame.ProtocolVersion, keyID, ts, nonce, scope)
		sealed, err := sesame.Seal(aead, iv, aad, xml)
		if err != nil {
			panic(err)
		}
		body = sealed
		h.Encrypted = true
		h.EncKeyID = "enc-2026q1"
		h.IV = hex.EncodeToString(iv)
	} else {
		body = xml
	}

	canon := sesame.RequestCanonical("POST", path, ts, nonce, sesame.BodyHashHex(body), scope)
	key, _ := p.PrimarySigningKey(keyID)
	h.Signature = sesame.Sign(key, canon)

	target := "SportsFeed-East"
	ctx := sesame.RequestContext{Method: "POST", Path: path, TargetChannel: &target}
	v, err := sesame.VerifyRequest(sesame.DefaultConfig(), p, sesame.NewInMemoryReplayCache(300), ctx, h, body, now, tier)
	if err != nil {
		fmt.Fprintf(os.Stderr, "self-verify FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("POST %s  (Tier %d)\n", path, tier)
	show := func(name, val string) {
		if val != "" {
			fmt.Printf("  %s: %s\n", name, val)
		}
	}
	show(sesame.HeaderVersion, h.Version)
	show(sesame.HeaderKeyID, h.KeyID)
	show(sesame.HeaderTimestamp, h.Timestamp)
	show(sesame.HeaderNonce, h.Nonce)
	show(sesame.HeaderScope, h.Scope)
	if h.Encrypted {
		show(sesame.HeaderEncrypted, "true")
		show(sesame.HeaderEncKeyID, h.EncKeyID)
		show(sesame.HeaderIV, h.IV)
	}
	show(sesame.HeaderSignature, h.Signature)
	kind := "cleartext XML"
	if h.Encrypted {
		kind = "ciphertext||tag"
	}
	fmt.Printf("  body: %d bytes (%s)\n", len(body), kind)
	fmt.Printf("self-verify OK: achieved Tier %d\n", v.AchievedTier)
}

func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}
