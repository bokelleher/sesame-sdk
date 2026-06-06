// canonical.hpp: the canonical strings HMAC-SHA256 signs (SESAME draft v0.5).
// Byte-identical to the Rust crate's sesame::canonical.
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "sesame/crypto.hpp"
#include "sesame/hex.hpp"

namespace sesame::canonical {

/// Lowercase-hex SHA-256 of the (possibly-encrypted) body.
inline std::string body_hash_hex(const std::uint8_t* body, std::size_t len) {
    auto d = crypto::sha256(body, len);
    return hex_encode(d.data(), d.size());
}
inline std::string body_hash_hex(const Bytes& b) { return body_hash_hex(b.data(), b.size()); }

/// REQUEST canonical string: method LF path LF timestamp LF nonce LF body-hash
/// [LF scope]. `scope` is present only when Tier 2 is active.
inline std::string request_canonical(std::string_view method, std::string_view path,
                                     std::string_view timestamp, std::string_view nonce,
                                     std::string_view body_hash_hex,
                                     std::optional<std::string_view> scope) {
    std::string s;
    s.reserve(method.size() + path.size() + body_hash_hex.size() + 96);
    s.append(method);
    s.push_back('\n');
    s.append(path);
    s.push_back('\n');
    s.append(timestamp);
    s.push_back('\n');
    s.append(nonce);
    s.push_back('\n');
    s.append(body_hash_hex);
    if (scope) {
        s.push_back('\n');
        s.append(*scope);
    }
    return s;
}

/// RESPONSE canonical string: "RESPONSE" LF correlation LF timestamp LF nonce
/// LF body-hash [LF scope]. `correlation` is the acquisitionSignalID answered.
inline std::string response_canonical(std::string_view correlation, std::string_view timestamp,
                                      std::string_view nonce, std::string_view body_hash_hex,
                                      std::optional<std::string_view> scope) {
    std::string s;
    s.reserve(correlation.size() + body_hash_hex.size() + 96);
    s.append("RESPONSE");
    s.push_back('\n');
    s.append(correlation);
    s.push_back('\n');
    s.append(timestamp);
    s.push_back('\n');
    s.append(nonce);
    s.push_back('\n');
    s.append(body_hash_hex);
    if (scope) {
        s.push_back('\n');
        s.append(*scope);
    }
    return s;
}

}  // namespace sesame::canonical
