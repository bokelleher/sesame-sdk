// tier3.hpp: AES-256-GCM payload encryption (96-bit IV, 128-bit tag).
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

#include "sesame/hex.hpp"

namespace sesame::tier3 {

constexpr std::size_t KEY_LEN = 32;
constexpr std::size_t IV_LEN = 12;
constexpr std::size_t TAG_LEN = 16;

/// GCM associated data: version LF key-id LF timestamp LF nonce [LF scope].
Bytes aad_for_headers(std::string_view version, std::string_view key_id,
                      std::string_view timestamp, std::string_view nonce,
                      std::optional<std::string_view> scope);

/// Encrypt, returning `ciphertext || tag`.
Bytes seal(const std::array<std::uint8_t, KEY_LEN>& key,
           const std::array<std::uint8_t, IV_LEN>& iv, const Bytes& aad, const Bytes& plaintext);

/// Decrypt `ciphertext || tag`; nullopt on authentication failure.
std::optional<Bytes> open(const std::array<std::uint8_t, KEY_LEN>& key,
                          const std::array<std::uint8_t, IV_LEN>& iv, const Bytes& aad,
                          const Bytes& ct_and_tag);

}  // namespace sesame::tier3
