// message.hpp: SESAME header names, the error taxonomy (Appendix A.7), and the
// parsed header view.
#pragma once

#include <functional>
#include <optional>
#include <string>

namespace sesame {

namespace header {
inline constexpr const char* VERSION = "X-SESAME-Version";
inline constexpr const char* KEY_ID = "X-SESAME-KeyId";
inline constexpr const char* TIMESTAMP = "X-SESAME-Timestamp";
inline constexpr const char* NONCE = "X-SESAME-Nonce";
inline constexpr const char* SIGNATURE = "X-SESAME-Signature";
inline constexpr const char* SCOPE = "X-SESAME-Scope";
inline constexpr const char* ENCRYPTED = "X-SESAME-Encrypted";
inline constexpr const char* ENC_KEY_ID = "X-SESAME-EncKeyId";
inline constexpr const char* IV = "X-SESAME-IV";
}  // namespace header

inline constexpr const char* PROTOCOL_VERSION = "1.0";

/// Every distinct SESAME failure (Appendix A.7), fail-closed.
enum class SesameError {
    MissingHeaders,
    InvalidVersion,
    UnknownKey,
    ExpiredTimestamp,
    ReplayDetected,
    SignatureMismatch,
    ScopeDenied,
    DecryptFailed,
    KeyRevoked,
};

/// Stable wire error code (Appendix A.7, first column).
const char* error_code(SesameError e);
/// HTTP status (Appendix A.7, second column).
int error_http_status(SesameError e);

/// SESAME headers extracted from a request or response. Timestamp, nonce,
/// signature and IV are kept as their exact on-wire strings.
struct SesameHeaders {
    std::optional<std::string> version;
    std::optional<std::string> key_id;
    std::optional<std::string> timestamp;
    std::optional<std::string> nonce;
    std::optional<std::string> signature;
    std::optional<std::string> scope;
    bool encrypted = false;
    std::optional<std::string> enc_key_id;
    std::optional<std::string> iv;

    /// True when no Tier-1 headers are present (Tier 0).
    bool is_absent() const;

    /// Parse from a case-insensitive `name -> value` lookup.
    static SesameHeaders from_lookup(
        const std::function<std::optional<std::string>(const char*)>& get);
};

}  // namespace sesame
