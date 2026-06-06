// hex.hpp: lowercase hex encode/decode, matching the SESAME wire encoding.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sesame {

using Bytes = std::vector<std::uint8_t>;

inline std::string hex_encode(const std::uint8_t* data, std::size_t len) {
    static const char* lut = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(lut[data[i] >> 4]);
        out.push_back(lut[data[i] & 0x0f]);
    }
    return out;
}

inline std::string hex_encode(const Bytes& b) {
    return hex_encode(b.data(), b.size());
}

// Decode lowercase or uppercase hex. Returns nullopt on odd length or a
// non-hex digit (matching rust-pois message::hex_decode).
inline std::optional<Bytes> hex_decode(std::string_view s) {
    if (s.size() % 2 != 0) return std::nullopt;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    Bytes out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i < s.size(); i += 2) {
        int hi = val(s[i]);
        int lo = val(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

}  // namespace sesame
