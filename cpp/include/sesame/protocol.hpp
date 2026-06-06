// protocol.hpp: the high-level SESAME API, mirroring the Rust crate's
// verify_request / sign_response. Framework-agnostic: callers pass the request
// parts, parsed headers, body, and `now` (Unix seconds).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "sesame/hex.hpp"
#include "sesame/keys.hpp"
#include "sesame/message.hpp"
#include "sesame/replay.hpp"

namespace sesame {

/// Additive security tiers (Tier N implies 1..N).
enum class Tier { Zero = 0, One = 1, Two = 2, Three = 3 };

struct SesameConfig {
    std::int64_t replay_window_secs = 300;
};

struct VerifiedRequest {
    Bytes plaintext;                          // decrypted ESAM XML (== body if not Tier 3)
    std::string key_id;                       // authenticated signing key-id
    std::optional<std::string> scope_channel; // present iff Tier 2
    Tier achieved_tier = Tier::Zero;
};

struct RequestContext {
    std::string method;
    std::string path;                          // request-target as signed (path + query)
    std::optional<std::string> target_channel; // cross-checked against the Tier-2 scope
};

/// Result of `verify_request`: either a VerifiedRequest or a SesameError.
struct VerifyResult {
    bool ok = false;
    SesameError error = SesameError::MissingHeaders;
    VerifiedRequest value;

    explicit operator bool() const { return ok; }
    static VerifyResult success(VerifiedRequest v) {
        VerifyResult r;
        r.ok = true;
        r.value = std::move(v);
        return r;
    }
    static VerifyResult failure(SesameError e) {
        VerifyResult r;
        r.ok = false;
        r.error = e;
        return r;
    }
};

/// Verify an inbound ESAM request. Fails closed at each step (Appendix A.7).
VerifyResult verify_request(const SesameConfig& cfg, const KeyProvider& provider,
                            ReplayCache& replay, const RequestContext& ctx,
                            const SesameHeaders& headers, const Bytes& raw_body,
                            std::int64_t now_unix, Tier min_tier);

struct SignedResponse {
    std::vector<std::pair<std::string, std::string>> headers;  // (name, value)
    Bytes body;                                                // ciphertext when Tier 3, else XML
    std::string content_type;
};

struct ResponseParams {
    std::string signing_key_id;
    std::string correlation;            // acquisitionSignalID answered
    std::optional<std::string> scope;   // "channel=<id>" (Tier 2+)
    Tier tier = Tier::One;
    std::optional<std::string> enc_key_id;  // Tier 3
};

struct SignResult {
    bool ok = false;
    SesameError error = SesameError::UnknownKey;
    SignedResponse value;

    explicit operator bool() const { return ok; }
    static SignResult success(SignedResponse v) {
        SignResult r;
        r.ok = true;
        r.value = std::move(v);
        return r;
    }
    static SignResult failure(SesameError e) {
        SignResult r;
        r.ok = false;
        r.error = e;
        return r;
    }
};

/// Sign (and optionally encrypt) an outbound ESAM response. A fresh nonce and
/// (for Tier 3) IV are drawn from the OS CSPRNG per call.
SignResult sign_response(const SesameConfig& cfg, const KeyProvider& provider,
                         const ResponseParams& params, const Bytes& plaintext_xml,
                         std::int64_t now_unix);

/// Format Unix seconds as an RFC-3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
std::string format_rfc3339_utc(std::int64_t unix_secs);

/// Parse `channel=<id>` from an X-SESAME-Scope value.
std::optional<std::string> parse_scope_channel(const std::string& scope);

}  // namespace sesame
