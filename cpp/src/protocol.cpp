#include "sesame/protocol.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <string_view>

#include "civil_time.h"
#include "sesame/canonical.hpp"
#include "sesame/tier1.hpp"
#include "sesame/tier3.hpp"

namespace sesame {

static int level(Tier t) { return static_cast<int>(t); }

std::string format_rfc3339_utc(std::int64_t unix_secs) {
    std::int64_t days = unix_secs / 86400;
    std::int64_t rem = unix_secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    std::int64_t y;
    unsigned mo, d;
    detail::civil_from_days(days, y, mo, d);
    const int hh = static_cast<int>(rem / 3600);
    const int mm = static_cast<int>((rem % 3600) / 60);
    const int ss = static_cast<int>(rem % 60);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02d:%02d:%02dZ",
                  static_cast<long long>(y), mo, d, hh, mm, ss);
    return std::string(buf);
}

std::optional<std::string> parse_scope_channel(const std::string& scope) {
    const std::string prefix = "channel=";
    if (scope.rfind(prefix, 0) != 0) return std::nullopt;
    std::string c = scope.substr(prefix.size());
    std::size_t b = 0, e = c.size();
    while (b < e && std::isspace(static_cast<unsigned char>(c[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(c[e - 1]))) --e;
    return c.substr(b, e - b);
}

static std::optional<Bytes> random_bytes(std::size_t n) {
    Bytes b(n);
    if (RAND_bytes(b.data(), static_cast<int>(n)) != 1) return std::nullopt;
    return b;
}

VerifyResult verify_request(const SesameConfig& cfg, const KeyProvider& provider,
                            ReplayCache& replay, const RequestContext& ctx,
                            const SesameHeaders& headers, const Bytes& raw_body,
                            std::int64_t now_unix, Tier min_tier) {
    // Tier 0: unauthenticated passthrough, only when policy permits it.
    if (headers.is_absent()) {
        if (min_tier == Tier::Zero) {
            VerifiedRequest v;
            v.plaintext = raw_body;
            v.achieved_tier = Tier::Zero;
            return VerifyResult::success(std::move(v));
        }
        return VerifyResult::failure(SesameError::MissingHeaders);
    }

    // Tier 1: required headers.
    if (!headers.version || !headers.key_id || !headers.timestamp || !headers.nonce ||
        !headers.signature)
        return VerifyResult::failure(SesameError::MissingHeaders);
    const std::string& version = *headers.version;
    const std::string& key_id = *headers.key_id;
    const std::string& timestamp = *headers.timestamp;
    const std::string& nonce = *headers.nonce;
    const std::string& signature = *headers.signature;

    if (version != PROTOCOL_VERSION) return VerifyResult::failure(SesameError::InvalidVersion);

    if (!tier1::check_freshness(timestamp, now_unix, cfg.replay_window_secs))
        return VerifyResult::failure(SesameError::ExpiredTimestamp);

    if (provider.is_revoked(key_id)) return VerifyResult::failure(SesameError::KeyRevoked);
    auto signing_keys = provider.signing_keys(key_id);
    if (signing_keys.empty()) return VerifyResult::failure(SesameError::UnknownKey);

    std::optional<std::string> scope = headers.scope;
    std::optional<std::string_view> scope_sv =
        scope ? std::optional<std::string_view>(*scope) : std::nullopt;

    std::string body_hash = canonical::body_hash_hex(raw_body);
    std::string canon =
        canonical::request_canonical(ctx.method, ctx.path, timestamp, nonce, body_hash, scope_sv);
    if (!tier1::verify_any(signing_keys, canon, signature))
        return VerifyResult::failure(SesameError::SignatureMismatch);

    // Replay only after the signature is valid.
    if (!replay.check_and_remember(key_id, nonce, now_unix))
        return VerifyResult::failure(SesameError::ReplayDetected);

    Tier achieved = Tier::One;
    std::optional<std::string> scope_channel;

    // Tier 2.
    if (scope) {
        auto declared = parse_scope_channel(*scope);
        if (!declared) return VerifyResult::failure(SesameError::ScopeDenied);
        if (ctx.target_channel && *ctx.target_channel != *declared)
            return VerifyResult::failure(SesameError::ScopeDenied);
        if (!provider.is_authorized(key_id, *declared))
            return VerifyResult::failure(SesameError::ScopeDenied);
        scope_channel = *declared;
        achieved = Tier::Two;
    } else if (level(min_tier) >= level(Tier::Two)) {
        return VerifyResult::failure(SesameError::ScopeDenied);
    }

    // Tier 3.
    Bytes plaintext;
    if (headers.encrypted) {
        if (!headers.enc_key_id || !headers.iv)
            return VerifyResult::failure(SesameError::DecryptFailed);
        auto iv_bytes = hex_decode(*headers.iv);
        if (!iv_bytes || iv_bytes->size() != tier3::IV_LEN)
            return VerifyResult::failure(SesameError::DecryptFailed);
        std::array<std::uint8_t, tier3::IV_LEN> iv{};
        std::copy(iv_bytes->begin(), iv_bytes->end(), iv.begin());
        auto aead = provider.aead_key(*headers.enc_key_id);
        if (!aead) return VerifyResult::failure(SesameError::DecryptFailed);
        Bytes aad = tier3::aad_for_headers(version, key_id, timestamp, nonce, scope_sv);
        auto pt = tier3::open(*aead, iv, aad, raw_body);
        if (!pt) return VerifyResult::failure(SesameError::DecryptFailed);
        plaintext = std::move(*pt);
        achieved = Tier::Three;
    } else if (level(min_tier) >= level(Tier::Three)) {
        return VerifyResult::failure(SesameError::DecryptFailed);
    } else {
        plaintext = raw_body;
    }

    if (level(achieved) < level(min_tier))
        return VerifyResult::failure(SesameError::MissingHeaders);

    VerifiedRequest v;
    v.plaintext = std::move(plaintext);
    v.key_id = key_id;
    v.scope_channel = scope_channel;
    v.achieved_tier = achieved;
    return VerifyResult::success(std::move(v));
}

SignResult sign_response(const SesameConfig& cfg, const KeyProvider& provider,
                         const ResponseParams& params, const Bytes& plaintext_xml,
                         std::int64_t now_unix) {
    (void)cfg;
    auto signing_key = provider.primary_signing_key(params.signing_key_id);
    if (!signing_key) return SignResult::failure(SesameError::UnknownKey);

    std::string timestamp = format_rfc3339_utc(now_unix);
    auto nonce_bytes = random_bytes(16);
    if (!nonce_bytes) return SignResult::failure(SesameError::SignatureMismatch);
    std::string nonce = hex_encode(*nonce_bytes);

    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back(header::VERSION, PROTOCOL_VERSION);
    headers.emplace_back(header::KEY_ID, params.signing_key_id);
    headers.emplace_back(header::TIMESTAMP, timestamp);
    headers.emplace_back(header::NONCE, nonce);
    if (params.scope) headers.emplace_back(header::SCOPE, *params.scope);

    std::optional<std::string_view> scope_sv =
        params.scope ? std::optional<std::string_view>(*params.scope) : std::nullopt;

    Bytes body;
    std::string content_type;
    if (level(params.tier) >= level(Tier::Three)) {
        if (!params.enc_key_id) return SignResult::failure(SesameError::DecryptFailed);
        auto aead = provider.aead_key(*params.enc_key_id);
        if (!aead) return SignResult::failure(SesameError::DecryptFailed);
        auto iv_bytes = random_bytes(tier3::IV_LEN);
        if (!iv_bytes) return SignResult::failure(SesameError::DecryptFailed);
        std::array<std::uint8_t, tier3::IV_LEN> iv{};
        std::copy(iv_bytes->begin(), iv_bytes->end(), iv.begin());
        Bytes aad =
            tier3::aad_for_headers(PROTOCOL_VERSION, params.signing_key_id, timestamp, nonce, scope_sv);
        body = tier3::seal(*aead, iv, aad, plaintext_xml);
        headers.emplace_back(header::ENCRYPTED, "true");
        headers.emplace_back(header::ENC_KEY_ID, *params.enc_key_id);
        headers.emplace_back(header::IV, hex_encode(*iv_bytes));
        content_type = "application/octet-stream";
    } else {
        body = plaintext_xml;
        content_type = "application/xml";
    }

    std::string body_hash = canonical::body_hash_hex(body);
    std::string canon =
        canonical::response_canonical(params.correlation, timestamp, nonce, body_hash, scope_sv);
    headers.emplace_back(header::SIGNATURE, tier1::sign(*signing_key, canon));

    SignedResponse r;
    r.headers = std::move(headers);
    r.body = std::move(body);
    r.content_type = std::move(content_type);
    return SignResult::success(std::move(r));
}

}  // namespace sesame
