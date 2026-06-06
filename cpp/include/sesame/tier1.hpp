// tier1.hpp: HMAC-SHA256 authentication + integrity, plus timestamp freshness.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sesame/hex.hpp"

namespace sesame::tier1 {

/// Lowercase-hex HMAC-SHA256 of `canonical` under `key`.
std::string sign(const Bytes& key, std::string_view canonical);

/// Constant-time verification of a provided lowercase-hex signature.
bool verify(const Bytes& key, std::string_view canonical, std::string_view provided_hex);

/// Verify against any one of several candidate keys (rotation overlap window).
bool verify_any(const std::vector<Bytes>& keys, std::string_view canonical,
                std::string_view provided_hex);

/// Parse an RFC-3339 UTC timestamp of the SESAME wire form
/// `YYYY-MM-DDTHH:MM:SSZ` to Unix seconds. Sets `ok=false` on a malformed input.
std::int64_t parse_rfc3339_utc(std::string_view iso, bool& ok);

/// True iff `timestamp_iso` is within `±window_secs` of `now_unix`.
bool check_freshness(std::string_view timestamp_iso, std::int64_t now_unix,
                     std::int64_t window_secs);

}  // namespace sesame::tier1
