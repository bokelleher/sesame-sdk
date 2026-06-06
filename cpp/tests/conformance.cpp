// conformance.cpp: prove this C++ implementation reproduces the golden vectors
// (generated from the deployed rust-pois implementation) byte-for-byte. Same
// contract the Rust crate passes; this is what makes the C++ SDK a real second
// implementation of SESAME rather than a separate dialect.

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include "json.hpp"
#include "sesame/canonical.hpp"
#include "sesame/hex.hpp"
#include "sesame/tier1.hpp"
#include "sesame/tier3.hpp"

using nlohmann::json;
using namespace sesame;

static int g_failures = 0;

static void check_eq(const std::string& got, const std::string& want, const std::string& msg) {
    if (got != want) {
        std::cerr << "FAIL: " << msg << "\n  got:  " << got << "\n  want: " << want << "\n";
        ++g_failures;
    }
}

static json load(const std::string& name) {
    std::string path = std::string(SESAME_VECTORS_DIR) + "/" + name;
    std::ifstream f(path);
    if (!f) {
        std::cerr << "cannot open " << path << "\n";
        std::exit(2);
    }
    json j;
    f >> j;
    return j;
}

static std::optional<std::string> opt(const json& v) {
    return v.is_null() ? std::nullopt : std::optional<std::string>(v.get<std::string>());
}

static std::array<std::uint8_t, 32> arr32(const std::string& hex) {
    auto b = hex_decode(hex).value();
    std::array<std::uint8_t, 32> a{};
    std::copy_n(b.begin(), 32, a.begin());
    return a;
}
static std::array<std::uint8_t, 12> arr12(const std::string& hex) {
    auto b = hex_decode(hex).value();
    std::array<std::uint8_t, 12> a{};
    std::copy_n(b.begin(), 12, a.begin());
    return a;
}

static void tier1_requests() {
    json file = load("tier1.json");
    for (const auto& v : file["request_vectors"]) {
        std::string name = v["name"];
        Bytes body = hex_decode(v["body_hex"].get<std::string>()).value();
        std::string bh = canonical::body_hash_hex(body);
        auto scope = opt(v["scope"]);
        std::string canon = canonical::request_canonical(
            v["method"].get<std::string>(), v["path"].get<std::string>(),
            v["timestamp"].get<std::string>(), v["nonce"].get<std::string>(), bh,
            scope ? std::optional<std::string_view>(*scope) : std::nullopt);
        check_eq(canon, v["expected_canonical"], "request canonical: " + name);

        Bytes key = hex_decode(v["signing_key_hex"].get<std::string>()).value();
        check_eq(tier1::sign(key, canon), v["expected_signature_hex"], "request signature: " + name);
    }
}

static void tier1_responses() {
    json file = load("tier1.json");
    for (const auto& v : file["response_vectors"]) {
        std::string name = v["name"];
        Bytes body = hex_decode(v["body_hex"].get<std::string>()).value();
        std::string bh = canonical::body_hash_hex(body);
        auto scope = opt(v["scope"]);
        std::string canon = canonical::response_canonical(
            v["correlation"].get<std::string>(), v["timestamp"].get<std::string>(),
            v["nonce"].get<std::string>(), bh,
            scope ? std::optional<std::string_view>(*scope) : std::nullopt);
        check_eq(canon, v["expected_canonical"], "response canonical: " + name);

        Bytes key = hex_decode(v["signing_key_hex"].get<std::string>()).value();
        check_eq(tier1::sign(key, canon), v["expected_signature_hex"], "response signature: " + name);
    }
}

static void tier3_aead() {
    json file = load("tier3.json");
    for (const auto& v : file["aead_vectors"]) {
        std::string name = v["name"];
        auto scope = opt(v["scope"]);
        Bytes aad = tier3::aad_for_headers(
            v["version"].get<std::string>(), v["key_id"].get<std::string>(),
            v["timestamp"].get<std::string>(), v["nonce"].get<std::string>(),
            scope ? std::optional<std::string_view>(*scope) : std::nullopt);
        check_eq(std::string(aad.begin(), aad.end()), v["expected_aad_utf8"], "aad: " + name);

        auto key = arr32(v["enc_key_hex"].get<std::string>());
        auto iv = arr12(v["iv_hex"].get<std::string>());
        Bytes pt = hex_decode(v["plaintext_hex"].get<std::string>()).value();
        Bytes body = tier3::seal(key, iv, aad, pt);
        check_eq(hex_encode(body), v["expected_body_hex"], "ciphertext||tag: " + name);

        auto recovered = tier3::open(key, iv, aad, body);
        if (!recovered || *recovered != pt) {
            std::cerr << "FAIL: decrypt round-trip: " << name << "\n";
            ++g_failures;
        }
    }
}

int main() {
    tier1_requests();
    tier1_responses();
    tier3_aead();
    if (g_failures == 0) {
        std::cout << "conformance: all golden vectors reproduced byte-for-byte\n";
        return 0;
    }
    std::cerr << "conformance: " << g_failures << " failure(s)\n";
    return 1;
}
