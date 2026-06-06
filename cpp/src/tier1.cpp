#include "sesame/tier1.hpp"

#include <cstddef>

#include "civil_time.h"
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

namespace {
// Parse `count` ASCII digits at iso[pos]; -1 on any non-digit.
int parse_digits(std::string_view iso, std::size_t pos, std::size_t count) {
    int v = 0;
    for (std::size_t i = 0; i < count; ++i) {
        char c = iso[pos + i];
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
    }
    return v;
}
}  // namespace

std::int64_t parse_rfc3339_utc(std::string_view iso, bool& ok) {
    ok = false;
    // Exactly the SESAME wire form: YYYY-MM-DDTHH:MM:SSZ.
    if (iso.size() != 20) return 0;
    if (iso[4] != '-' || iso[7] != '-' || iso[10] != 'T' || iso[13] != ':' ||
        iso[16] != ':' || iso[19] != 'Z')
        return 0;
    int year = parse_digits(iso, 0, 4);
    int mon = parse_digits(iso, 5, 2);
    int day = parse_digits(iso, 8, 2);
    int hour = parse_digits(iso, 11, 2);
    int min = parse_digits(iso, 14, 2);
    int sec = parse_digits(iso, 17, 2);
    if (year < 0 || mon < 1 || mon > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 ||
        min < 0 || min > 59 || sec < 0 || sec > 59)
        return 0;
    ok = true;
    return detail::days_from_civil(year, static_cast<unsigned>(mon), static_cast<unsigned>(day)) *
               86400 +
           static_cast<std::int64_t>(hour) * 3600 + static_cast<std::int64_t>(min) * 60 + sec;
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
