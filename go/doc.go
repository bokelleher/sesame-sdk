// Package sesame is a native Go implementation of SESAME (Secure ESAM
// Authentication and Message Encryption), the proposed SCTE 130-9 security
// layer for the ESAM interface (draft v0.5).
//
// It has zero external dependencies: the cryptography comes entirely from the
// Go standard library (crypto/hmac, crypto/sha256, crypto/aes, crypto/cipher).
// It is proven byte-for-byte against the same golden vectors as the Rust crate,
// the C++ SDK, and the Python SDK, so a Go signer and a verifier in any of them
// interoperate exactly.
package sesame
