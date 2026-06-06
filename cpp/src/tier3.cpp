#include "sesame/tier3.hpp"

#include <string>

#include "sesame/crypto.hpp"

namespace sesame::tier3 {

Bytes aad_for_headers(std::string_view version, std::string_view key_id,
                      std::string_view timestamp, std::string_view nonce,
                      std::optional<std::string_view> scope) {
    std::string s;
    s.append(version);
    s.push_back('\n');
    s.append(key_id);
    s.push_back('\n');
    s.append(timestamp);
    s.push_back('\n');
    s.append(nonce);
    if (scope) {
        s.push_back('\n');
        s.append(*scope);
    }
    return Bytes(s.begin(), s.end());
}

Bytes seal(const std::array<std::uint8_t, KEY_LEN>& key,
           const std::array<std::uint8_t, IV_LEN>& iv, const Bytes& aad, const Bytes& plaintext) {
    return crypto::aes256gcm_seal(key, iv, aad.data(), aad.size(), plaintext.data(),
                                  plaintext.size());
}

std::optional<Bytes> open(const std::array<std::uint8_t, KEY_LEN>& key,
                          const std::array<std::uint8_t, IV_LEN>& iv, const Bytes& aad,
                          const Bytes& ct_and_tag) {
    return crypto::aes256gcm_open(key, iv, aad.data(), aad.size(), ct_and_tag.data(),
                                  ct_and_tag.size());
}

}  // namespace sesame::tier3
