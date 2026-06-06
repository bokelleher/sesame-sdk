// sign_request.cpp: a minimal SESAME client. Builds a signed (and optionally
// AES-256-GCM-encrypted) ESAM request using this SDK's primitives, then
// self-verifies it with verify_request (the same oracle a server runs) before
// it would go on the wire. Prints the headers and body it would send.
//
// Build: configured by the top-level CMake (target `sign_request`).
// Run:   ./build/sign_request [1|2|3]      # tier, default 1

#include <openssl/rand.h>

#include <array>
#include <ctime>
#include <iostream>
#include <string>

#include "sesame/sesame.hpp"

using namespace sesame;

static Bytes str_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

int main(int argc, char** argv) {
    int tier_n = (argc > 1) ? std::atoi(argv[1]) : 1;
    Tier tier = (tier_n >= 3) ? Tier::Three : (tier_n == 2) ? Tier::Two : Tier::One;

    // A demo key directory (in production these come from your secret store).
    StaticKeyProvider provider;
    provider
        .with_signing_key("sas-east-01", str_bytes("shared-secret"),
                          ChannelScope::list({"SportsFeed-East"}))
        .with_aead_key("enc-2026q1",
                       std::array<std::uint8_t, 32>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                                                    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                                                    27, 28, 29, 30, 31, 32});

    const std::string xml = "<?xml version=\"1.0\"?><SignalProcessingNotification/>";
    const std::string path = "/esam?channel=SportsFeed-East";
    const std::string key_id = "sas-east-01";

    // Fresh timestamp and nonce.
    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    std::string timestamp = format_rfc3339_utc(now);
    std::array<std::uint8_t, 16> nonce_bytes{};
    RAND_bytes(nonce_bytes.data(), static_cast<int>(nonce_bytes.size()));
    std::string nonce = hex_encode(nonce_bytes.data(), nonce_bytes.size());

    std::optional<std::string> scope =
        (static_cast<int>(tier) >= 2) ? std::optional<std::string>("channel=SportsFeed-East")
                                      : std::nullopt;
    std::optional<std::string_view> scope_sv =
        scope ? std::optional<std::string_view>(*scope) : std::nullopt;

    SesameHeaders headers;
    headers.version = PROTOCOL_VERSION;
    headers.key_id = key_id;
    headers.timestamp = timestamp;
    headers.nonce = nonce;
    headers.scope = scope;

    Bytes body;
    if (static_cast<int>(tier) >= 3) {
        auto aead = provider.aead_key("enc-2026q1").value();
        std::array<std::uint8_t, 12> iv{};
        RAND_bytes(iv.data(), static_cast<int>(iv.size()));
        Bytes aad = tier3::aad_for_headers(PROTOCOL_VERSION, key_id, timestamp, nonce, scope_sv);
        body = tier3::seal(aead, iv, aad, str_bytes(xml));
        headers.encrypted = true;
        headers.enc_key_id = "enc-2026q1";
        headers.iv = hex_encode(iv.data(), iv.size());
    } else {
        body = str_bytes(xml);
    }

    std::string body_hash = canonical::body_hash_hex(body);
    std::string canon = canonical::request_canonical("POST", path, timestamp, nonce, body_hash,
                                                     scope_sv);
    headers.signature = tier1::sign(provider.primary_signing_key(key_id).value(), canon);

    // Self-check: verify what we just built, exactly as a server would.
    InMemoryReplayCache replay(300);
    RequestContext ctx{"POST", path, std::optional<std::string>("SportsFeed-East")};
    auto verified = verify_request(SesameConfig{}, provider, replay, ctx, headers, body, now, tier);
    if (!verified.ok) {
        std::cerr << "self-verify FAILED: " << error_code(verified.error) << "\n";
        return 1;
    }

    std::cout << "POST " << path << "  (Tier " << static_cast<int>(tier) << ")\n";
    auto print = [](const char* n, const std::optional<std::string>& v) {
        if (v) std::cout << "  " << n << ": " << *v << "\n";
    };
    print(header::VERSION, headers.version);
    print(header::KEY_ID, headers.key_id);
    print(header::TIMESTAMP, headers.timestamp);
    print(header::NONCE, headers.nonce);
    print(header::SCOPE, headers.scope);
    if (headers.encrypted) {
        std::cout << "  " << header::ENCRYPTED << ": true\n";
        print(header::ENC_KEY_ID, headers.enc_key_id);
        print(header::IV, headers.iv);
    }
    print(header::SIGNATURE, headers.signature);
    std::cout << "  body: " << body.size() << " bytes"
              << (headers.encrypted ? " (ciphertext||tag)" : " (cleartext XML)") << "\n";
    std::cout << "self-verify OK: achieved Tier " << static_cast<int>(verified.value.achieved_tier)
              << "\n";
    return 0;
}
