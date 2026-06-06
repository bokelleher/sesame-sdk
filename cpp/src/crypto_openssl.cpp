// crypto_openssl.cpp: OpenSSL 3.x implementation of the SESAME crypto seam.
// Uses the non-deprecated EVP interfaces (EVP_Digest, EVP_MAC, EVP_CIPHER).

#include "sesame/crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdexcept>

namespace sesame::crypto {

namespace {
struct CipherCtx {
    EVP_CIPHER_CTX* p = EVP_CIPHER_CTX_new();
    ~CipherCtx() { EVP_CIPHER_CTX_free(p); }
};
[[noreturn]] void fail(const char* what) { throw std::runtime_error(std::string("sesame crypto: ") + what); }
}  // namespace

std::array<std::uint8_t, SHA256_LEN> sha256(const std::uint8_t* data, std::size_t len) {
    std::array<std::uint8_t, SHA256_LEN> out{};
    unsigned int out_len = 0;
    if (EVP_Digest(data, len, out.data(), &out_len, EVP_sha256(), nullptr) != 1)
        fail("sha256");
    return out;
}

std::array<std::uint8_t, SHA256_LEN> hmac_sha256(const std::uint8_t* key, std::size_t key_len,
                                                 const std::uint8_t* data, std::size_t len) {
    std::array<std::uint8_t, SHA256_LEN> out{};
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) fail("HMAC fetch");
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); fail("HMAC ctx"); }

    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("digest", digest, 0),
                           OSSL_PARAM_construct_end()};
    // HMAC accepts any key length; pass a non-null pointer even for empty keys.
    static const std::uint8_t empty = 0;
    const std::uint8_t* k = (key_len == 0) ? &empty : key;
    std::size_t out_len = 0;
    bool ok = EVP_MAC_init(ctx, k, key_len, params) == 1 &&
              EVP_MAC_update(ctx, data, len) == 1 &&
              EVP_MAC_final(ctx, out.data(), &out_len, out.size()) == 1;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    if (!ok || out_len != SHA256_LEN) fail("HMAC compute");
    return out;
}

Bytes aes256gcm_seal(const std::array<std::uint8_t, AES256_KEY_LEN>& key,
                     const std::array<std::uint8_t, GCM_IV_LEN>& iv, const std::uint8_t* aad,
                     std::size_t aad_len, const std::uint8_t* plaintext, std::size_t pt_len) {
    CipherCtx c;
    if (!c.p) fail("cipher ctx");
    int outl = 0;
    if (EVP_EncryptInit_ex(c.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.p, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(c.p, nullptr, nullptr, key.data(), iv.data()) != 1)
        fail("gcm encrypt init");

    if (aad_len && EVP_EncryptUpdate(c.p, nullptr, &outl, aad, static_cast<int>(aad_len)) != 1)
        fail("gcm aad");

    Bytes out(pt_len + GCM_TAG_LEN);
    int ct_len = 0;
    if (pt_len) {
        if (EVP_EncryptUpdate(c.p, out.data(), &outl, plaintext, static_cast<int>(pt_len)) != 1)
            fail("gcm encrypt");
        ct_len = outl;
    }
    if (EVP_EncryptFinal_ex(c.p, out.data() + ct_len, &outl) != 1) fail("gcm final");
    ct_len += outl;
    if (EVP_CIPHER_CTX_ctrl(c.p, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, out.data() + ct_len) != 1)
        fail("gcm tag");
    out.resize(ct_len + GCM_TAG_LEN);
    return out;
}

std::optional<Bytes> aes256gcm_open(const std::array<std::uint8_t, AES256_KEY_LEN>& key,
                                    const std::array<std::uint8_t, GCM_IV_LEN>& iv,
                                    const std::uint8_t* aad, std::size_t aad_len,
                                    const std::uint8_t* ct_and_tag, std::size_t len) {
    if (len < GCM_TAG_LEN) return std::nullopt;
    const std::size_t ct_len = len - GCM_TAG_LEN;
    const std::uint8_t* tag = ct_and_tag + ct_len;

    CipherCtx c;
    if (!c.p) return std::nullopt;
    int outl = 0;
    if (EVP_DecryptInit_ex(c.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.p, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(c.p, nullptr, nullptr, key.data(), iv.data()) != 1)
        return std::nullopt;

    if (aad_len && EVP_DecryptUpdate(c.p, nullptr, &outl, aad, static_cast<int>(aad_len)) != 1)
        return std::nullopt;

    Bytes out(ct_len);
    int pt_len = 0;
    if (ct_len) {
        if (EVP_DecryptUpdate(c.p, out.data(), &outl, ct_and_tag, static_cast<int>(ct_len)) != 1)
            return std::nullopt;
        pt_len = outl;
    }
    if (EVP_CIPHER_CTX_ctrl(c.p, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                            const_cast<std::uint8_t*>(tag)) != 1)
        return std::nullopt;
    if (EVP_DecryptFinal_ex(c.p, out.data() + pt_len, &outl) <= 0)
        return std::nullopt;  // tag mismatch
    out.resize(pt_len + outl);
    return out;
}

bool constant_time_eq(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}

}  // namespace sesame::crypto
