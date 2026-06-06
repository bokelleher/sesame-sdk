// unit.cpp: known-answer tests (RFC 4231, NIST SP 800-38D), plus a full
// sign/verify round-trip and the negative matrix, mirroring the Rust crate's
// in-tree tests.

#include <array>
#include <iostream>
#include <string>

#include "sesame/canonical.hpp"
#include "sesame/crypto.hpp"
#include "sesame/hex.hpp"
#include "sesame/keys.hpp"
#include "sesame/protocol.hpp"
#include "sesame/replay.hpp"
#include "sesame/tier1.hpp"
#include "sesame/tier3.hpp"

using namespace sesame;

static int g_fail = 0;
#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (!(cond)) {                                                \
            std::cerr << "FAIL: " << (msg) << "\n";                   \
            ++g_fail;                                                 \
        }                                                             \
    } while (0)

static Bytes hx(const std::string& s) { return hex_decode(s).value(); }
static std::array<std::uint8_t, 32> a32(const std::string& s) {
    auto b = hx(s);
    std::array<std::uint8_t, 32> a{};
    std::copy_n(b.begin(), 32, a.begin());
    return a;
}
static std::array<std::uint8_t, 12> a12(const std::string& s) {
    auto b = hx(s);
    std::array<std::uint8_t, 12> a{};
    std::copy_n(b.begin(), 12, a.begin());
    return a;
}
static Bytes str_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

static void known_answer_tests() {
    // SHA-256 of the empty string.
    CHECK(canonical::body_hash_hex(Bytes{}) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "sha256 empty");

    // RFC 4231 Test Case 2 (HMAC-SHA256).
    CHECK(tier1::sign(str_bytes("Jefe"), "what do ya want for nothing?") ==
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          "rfc4231 hmac");

    // NIST SP 800-38D AES-256-GCM Test Case 16 (ciphertext||tag).
    auto key = a32("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    auto iv = a12("cafebabefacedbaddecaf888");
    Bytes pt = hx(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    Bytes aad = hx("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    Bytes expected = hx(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        "76fc6ece0f4e1768cddf8853bb2d551b");
    CHECK(crypto::aes256gcm_seal(key, iv, aad.data(), aad.size(), pt.data(), pt.size()) == expected,
          "nist gcm");

    // hex round-trip.
    CHECK(hex_encode(hx("000fa1ff10")) == "000fa1ff10", "hex roundtrip");
    CHECK(!hex_decode("abc").has_value(), "hex odd-length rejected");

    // freshness window (±300s, inclusive edge).
    bool ok_now = false;
    std::int64_t now = tier1::parse_rfc3339_utc("2026-02-24T18:05:00Z", ok_now);
    CHECK(tier1::check_freshness("2026-02-24T18:00:00Z", now, 300), "fresh at edge");
    CHECK(!tier1::check_freshness("2026-02-24T17:59:59Z", now, 300), "stale past edge");
    CHECK(!tier1::check_freshness("not-a-date", now, 300), "unparseable rejected");
}

static StaticKeyProvider provider() {
    StaticKeyProvider p;
    p.with_signing_key("sas-east-01", str_bytes("client-secret"),
                       ChannelScope::list({"SportsFeed-East"}))
        .with_signing_key("pois-primary", str_bytes("pois-secret"), ChannelScope::all())
        .with_aead_key("enc-sportsfeed-2026q1", a32("42424242424242424242424242424242"
                                                    "42424242424242424242424242424242"));
    return p;
}

static const char* XML = "<?xml version=\"1.0\"?><SignalProcessingEvent/>";

// Build a signed request the way a conformant client would (fixed nonce/iv).
static SesameHeaders make_request(Tier tier, Bytes& body_out, const StaticKeyProvider& p) {
    std::string ts = "2026-02-24T18:00:00Z";
    std::string nonce = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    std::optional<std::string> scope =
        (static_cast<int>(tier) >= 2) ? std::optional<std::string>("channel=SportsFeed-East")
                                      : std::nullopt;
    std::optional<std::string_view> scope_sv =
        scope ? std::optional<std::string_view>(*scope) : std::nullopt;

    SesameHeaders h;
    h.version = PROTOCOL_VERSION;
    h.key_id = "sas-east-01";
    h.timestamp = ts;
    h.nonce = nonce;
    h.scope = scope;

    Bytes body;
    if (static_cast<int>(tier) >= 3) {
        auto aead = p.aead_key("enc-sportsfeed-2026q1").value();
        std::array<std::uint8_t, 12> iv{};  // fixed zero IV for the test
        Bytes aad = tier3::aad_for_headers(PROTOCOL_VERSION, "sas-east-01", ts, nonce, scope_sv);
        body = tier3::seal(aead, iv, aad, str_bytes(XML));
        h.encrypted = true;
        h.enc_key_id = "enc-sportsfeed-2026q1";
        h.iv = hex_encode(iv.data(), iv.size());
    } else {
        body = str_bytes(XML);
    }

    std::string bh = canonical::body_hash_hex(body);
    std::string canon = canonical::request_canonical(
        "POST", "/esam?channel=SportsFeed-East", ts, nonce, bh, scope_sv);
    h.signature = tier1::sign(p.primary_signing_key("sas-east-01").value(), canon);
    body_out = std::move(body);
    return h;
}

static RequestContext ctx() {
    return RequestContext{"POST", "/esam?channel=SportsFeed-East",
                          std::optional<std::string>("SportsFeed-East")};
}

static std::int64_t now() {
    bool ok = false;
    return tier1::parse_rfc3339_utc("2026-02-24T18:00:00Z", ok);
}

static void roundtrip_and_negatives() {
    auto p = provider();
    SesameConfig cfg;

    // Positive Tier 1/2/3.
    for (Tier t : {Tier::One, Tier::Two, Tier::Three}) {
        Bytes body;
        auto h = make_request(t, body, p);
        InMemoryReplayCache cache(300);
        auto r = verify_request(cfg, p, cache, ctx(), h, body, now(), t);
        CHECK(r.ok, std::string("tier ") + std::to_string(static_cast<int>(t)) + " verifies");
        if (r.ok) {
            CHECK(r.value.plaintext == str_bytes(XML),
                  "tier " + std::to_string(static_cast<int>(t)) + " plaintext");
            CHECK(r.value.achieved_tier == t, "achieved tier");
        }
    }

    // Tampered body.
    {
        Bytes body;
        auto h = make_request(Tier::One, body, p);
        body.push_back('X');
        InMemoryReplayCache cache(300);
        auto r = verify_request(cfg, p, cache, ctx(), h, body, now(), Tier::One);
        CHECK(!r.ok && r.error == SesameError::SignatureMismatch, "tampered body rejected");
    }
    // Replay.
    {
        Bytes body;
        auto h = make_request(Tier::One, body, p);
        InMemoryReplayCache cache(300);
        CHECK(verify_request(cfg, p, cache, ctx(), h, body, now(), Tier::One).ok, "first ok");
        auto r = verify_request(cfg, p, cache, ctx(), h, body, now(), Tier::One);
        CHECK(!r.ok && r.error == SesameError::ReplayDetected, "replay rejected");
    }
    // Stale.
    {
        Bytes body;
        auto h = make_request(Tier::One, body, p);
        InMemoryReplayCache cache(300);
        auto r = verify_request(cfg, p, cache, ctx(), h, body, now() + 600, Tier::One);
        CHECK(!r.ok && r.error == SesameError::ExpiredTimestamp, "stale rejected");
    }
    // Unknown key.
    {
        Bytes body;
        auto h = make_request(Tier::One, body, p);
        h.key_id = "ghost";
        InMemoryReplayCache cache(300);
        auto r = verify_request(cfg, p, cache, ctx(), h, body, now(), Tier::One);
        CHECK(!r.ok && r.error == SesameError::UnknownKey, "unknown key rejected");
    }
    // Wrong version.
    {
        Bytes body;
        auto h = make_request(Tier::One, body, p);
        h.version = "2.0";
        InMemoryReplayCache cache(300);
        auto r = verify_request(cfg, p, cache, ctx(), h, body, now(), Tier::One);
        CHECK(!r.ok && r.error == SesameError::InvalidVersion, "wrong version rejected");
    }
    // Truncated GCM tag (body hash changes first -> signature mismatch).
    {
        Bytes body;
        auto h = make_request(Tier::Three, body, p);
        body.pop_back();
        InMemoryReplayCache cache(300);
        auto r = verify_request(cfg, p, cache, ctx(), h, body, now(), Tier::Three);
        CHECK(!r.ok && r.error == SesameError::SignatureMismatch, "truncated tag rejected");
    }

    // sign_response -> client re-derives + verifies (forged-response defense).
    {
        ResponseParams params;
        params.signing_key_id = "pois-primary";
        params.correlation = "ap-1:sig-001";
        params.scope = std::optional<std::string>("channel=SportsFeed-East");
        params.tier = Tier::Two;
        auto rr = sign_response(cfg, p, params, str_bytes(XML), now());
        CHECK(rr.ok, "sign_response ok");
        if (rr.ok) {
            auto get = [&](const char* n) -> std::string {
                for (auto& kv : rr.value.headers)
                    if (kv.first == n) return kv.second;
                return "";
            };
            std::string bh = canonical::body_hash_hex(rr.value.body);
            std::string canon = canonical::response_canonical(
                "ap-1:sig-001", get(header::TIMESTAMP), get(header::NONCE), bh,
                std::optional<std::string_view>("channel=SportsFeed-East"));
            auto key = p.primary_signing_key("pois-primary").value();
            CHECK(tier1::verify(key, canon, get(header::SIGNATURE)), "response verifies");
            // Forged decision body fails.
            std::string forged_bh = canonical::body_hash_hex(str_bytes("<blackout/>"));
            std::string forged = canonical::response_canonical(
                "ap-1:sig-001", get(header::TIMESTAMP), get(header::NONCE), forged_bh,
                std::optional<std::string_view>("channel=SportsFeed-East"));
            CHECK(!tier1::verify(key, forged, get(header::SIGNATURE)), "forged response rejected");
        }
    }
}

int main() {
    known_answer_tests();
    roundtrip_and_negatives();
    if (g_fail == 0) {
        std::cout << "unit: all checks passed\n";
        return 0;
    }
    std::cerr << "unit: " << g_fail << " failure(s)\n";
    return 1;
}
