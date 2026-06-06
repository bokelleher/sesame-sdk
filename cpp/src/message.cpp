#include "sesame/message.hpp"

#include <algorithm>
#include <cctype>

namespace sesame {

const char* error_code(SesameError e) {
    switch (e) {
        case SesameError::MissingHeaders: return "sesame_missing_headers";
        case SesameError::InvalidVersion: return "sesame_invalid_version";
        case SesameError::UnknownKey: return "sesame_unknown_key";
        case SesameError::ExpiredTimestamp: return "sesame_expired_timestamp";
        case SesameError::ReplayDetected: return "sesame_replay_detected";
        case SesameError::SignatureMismatch: return "sesame_signature_mismatch";
        case SesameError::ScopeDenied: return "sesame_scope_denied";
        case SesameError::DecryptFailed: return "sesame_decrypt_failed";
        case SesameError::KeyRevoked: return "sesame_key_revoked";
    }
    return "sesame_unknown";
}

int error_http_status(SesameError e) {
    switch (e) {
        case SesameError::InvalidVersion:
        case SesameError::DecryptFailed: return 400;
        case SesameError::ScopeDenied: return 403;
        default: return 401;
    }
}

bool SesameHeaders::is_absent() const {
    return !version && !key_id && !timestamp && !nonce && !signature;
}

SesameHeaders SesameHeaders::from_lookup(
    const std::function<std::optional<std::string>(const char*)>& get) {
    SesameHeaders h;
    h.version = get(header::VERSION);
    h.key_id = get(header::KEY_ID);
    h.timestamp = get(header::TIMESTAMP);
    h.nonce = get(header::NONCE);
    h.signature = get(header::SIGNATURE);
    h.scope = get(header::SCOPE);
    h.enc_key_id = get(header::ENC_KEY_ID);
    h.iv = get(header::IV);
    if (auto e = get(header::ENCRYPTED)) {
        std::string v = *e;
        std::transform(v.begin(), v.end(), v.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        h.encrypted = (v == "true");
    }
    return h;
}

}  // namespace sesame
