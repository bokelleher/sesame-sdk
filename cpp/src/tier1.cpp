#include "sesame/tier1.hpp"

#include <time.h>

#include "sesame/crypto.hpp"

namespace sesame::tier1 {

static const std::uint8_t* as_bytes(std::string_view s) {
    return reinterpret_cast<const std::uint8_t*>(s.data());
}

std::string sign(const Bytes& key, std::string_view canonical) {
    auto mac = crypto::hmac_sha256(key.data(), key.size(), as_bytes(canonical), canonical.size());
    return hex_encode(mac.data(), mac.size());
}

bool verify(const Bytes& key, std::string_view canonical, std::string_view provided_hex) {
    auto provided = hex_decode(provided_hex);
    if (!provided || provided->size() != crypto::SHA256_LEN) return false;
    auto mac = crypto::hmac_sha256(key.data(), key.size(), as_bytes(canonical), canonical.size());
    return crypto::constant_time_eq(mac.data(), provided->data(), crypto::SHA256_LEN);
}

bool verify_any(const std::vector<Bytes>& keys, std::string_view canonical,
                std::string_view provided_hex) {
    bool ok = false;
    for (const auto& k : keys) {
        if (verify(k, canonical, provided_hex)) ok = true;  // no early-out
    }
    return ok;
}

std::int64_t parse_rfc3339_utc(std::string_view iso, bool& ok) {
    std::string s(iso);
    struct tm t {};
    const char* end = strptime(s.c_str(), "%Y-%m-%dT%H:%M:%SZ", &t);
    if (!end || *end != '\0') {
        ok = false;
        return 0;
    }
    ok = true;
    return static_cast<std::int64_t>(timegm(&t));
}

bool check_freshness(std::string_view timestamp_iso, std::int64_t now_unix,
                     std::int64_t window_secs) {
    bool ok = false;
    std::int64_t ts = parse_rfc3339_utc(timestamp_iso, ok);
    if (!ok) return false;
    std::int64_t delta = now_unix - ts;
    if (delta < 0) delta = -delta;
    return delta <= window_secs;
}

}  // namespace sesame::tier1
