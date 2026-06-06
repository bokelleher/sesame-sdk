// keys.hpp: key material and the KeyProvider lookup/authorization seam.
#pragma once

#include <array>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "sesame/hex.hpp"

namespace sesame {

/// The set of channels a signing key-id may act on (Tier 2 policy).
struct ChannelScope {
    bool allow_all = false;
    std::set<std::string> channels;

    static ChannelScope all() { return ChannelScope{true, {}}; }
    static ChannelScope list(std::initializer_list<std::string> c) {
        ChannelScope s;
        for (const auto& x : c) s.channels.insert(x);
        return s;
    }
    bool permits(const std::string& channel) const {
        return allow_all || channels.count(channel) > 0;
    }
};

/// Lookup seam for SESAME key material and authorization policy.
class KeyProvider {
public:
    virtual ~KeyProvider() = default;

    /// All currently-valid signing keys for `key_id` (more than one only during
    /// a rotation overlap). Empty => unknown key-id.
    virtual std::vector<Bytes> signing_keys(const std::string& key_id) const = 0;

    /// The primary signing key for `key_id`.
    virtual std::optional<Bytes> primary_signing_key(const std::string& key_id) const {
        auto v = signing_keys(key_id);
        if (v.empty()) return std::nullopt;
        return v.front();
    }

    /// The AEAD (encryption) key for `enc_key_id` (separate namespace).
    virtual std::optional<std::array<std::uint8_t, 32>> aead_key(
        const std::string& enc_key_id) const = 0;

    /// Whether `key_id` is authorized for `channel` (Tier 2).
    virtual bool is_authorized(const std::string& key_id, const std::string& channel) const = 0;

    /// Whether `key_id` is explicitly revoked.
    virtual bool is_revoked(const std::string& key_id) const = 0;
};

/// In-memory, config-backed reference provider.
class StaticKeyProvider : public KeyProvider {
    struct Entry {
        std::vector<Bytes> keys;
        ChannelScope scope;
        bool revoked = false;
    };
    std::map<std::string, Entry> signing_;
    std::map<std::string, std::array<std::uint8_t, 32>> aead_;

public:
    StaticKeyProvider& with_signing_key(const std::string& id, Bytes key, ChannelScope scope) {
        signing_[id] = Entry{{std::move(key)}, std::move(scope), false};
        return *this;
    }
    StaticKeyProvider& add_overlap_key(const std::string& id, Bytes key) {
        signing_[id].keys.push_back(std::move(key));
        return *this;
    }
    StaticKeyProvider& revoke(const std::string& id) {
        auto it = signing_.find(id);
        if (it != signing_.end()) it->second.revoked = true;
        return *this;
    }
    StaticKeyProvider& with_aead_key(const std::string& id, std::array<std::uint8_t, 32> key) {
        aead_[id] = key;
        return *this;
    }

    std::vector<Bytes> signing_keys(const std::string& id) const override {
        auto it = signing_.find(id);
        return it == signing_.end() ? std::vector<Bytes>{} : it->second.keys;
    }
    std::optional<std::array<std::uint8_t, 32>> aead_key(const std::string& id) const override {
        auto it = aead_.find(id);
        if (it == aead_.end()) return std::nullopt;
        return it->second;
    }
    bool is_authorized(const std::string& id, const std::string& channel) const override {
        auto it = signing_.find(id);
        return it != signing_.end() && !it->second.revoked && it->second.scope.permits(channel);
    }
    bool is_revoked(const std::string& id) const override {
        auto it = signing_.find(id);
        return it != signing_.end() && it->second.revoked;
    }
};

}  // namespace sesame
