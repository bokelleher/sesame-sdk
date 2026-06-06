// crypto.hpp: the cryptographic primitives SESAME needs, as a thin backend
// seam. The shipped implementation (src/crypto_openssl.cpp) uses OpenSSL 3.x;
// an embedded target could provide an mbedTLS/BoringSSL implementation of this
// same header without touching the protocol code.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "sesame/hex.hpp"  // Bytes

namespace sesame::crypto {

constexpr std::size_t SHA256_LEN = 32;
constexpr std::size_t AES256_KEY_LEN = 32;
constexpr std::size_t GCM_IV_LEN = 12;
constexpr std::size_t GCM_TAG_LEN = 16;

/// SHA-256 digest.
std::array<std::uint8_t, SHA256_LEN> sha256(const std::uint8_t* data, std::size_t len);

/// HMAC-SHA256. The key may be any length.
std::array<std::uint8_t, SHA256_LEN> hmac_sha256(const std::uint8_t* key, std::size_t key_len,
                                                 const std::uint8_t* data, std::size_t len);

/// AES-256-GCM encrypt. Returns ciphertext with the 16-byte tag appended
/// (`ciphertext || tag`), matching the SESAME wire format.
Bytes aes256gcm_seal(const std::array<std::uint8_t, AES256_KEY_LEN>& key,
                     const std::array<std::uint8_t, GCM_IV_LEN>& iv, const std::uint8_t* aad,
                     std::size_t aad_len, const std::uint8_t* plaintext, std::size_t pt_len);

/// AES-256-GCM decrypt of `ciphertext || tag`. Returns the plaintext, or
/// nullopt if authentication fails (wrong key/IV/AAD or tampered input).
std::optional<Bytes> aes256gcm_open(const std::array<std::uint8_t, AES256_KEY_LEN>& key,
                                    const std::array<std::uint8_t, GCM_IV_LEN>& iv,
                                    const std::uint8_t* aad, std::size_t aad_len,
                                    const std::uint8_t* ct_and_tag, std::size_t len);

/// Constant-time equality (for comparing MACs).
bool constant_time_eq(const std::uint8_t* a, const std::uint8_t* b, std::size_t len);

}  // namespace sesame::crypto
