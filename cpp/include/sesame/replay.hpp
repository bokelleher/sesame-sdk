// replay.hpp: the replay-cache seam and a single-node in-memory reference.
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>

namespace sesame {

/// Replay cache seam. `check_and_remember` atomically tests for a previously
/// seen (key_id, nonce) within the window and records it if new.
class ReplayCache {
public:
    virtual ~ReplayCache() = default;
    /// Returns true if fresh (and records it), false if already seen.
    virtual bool check_and_remember(const std::string& key_id, const std::string& nonce,
                                    std::int64_t now_unix) = 0;
};

/// In-memory TTL replay cache, bounded by the window. Per-process only;
/// horizontally-scaled deployments back this seam with a shared store.
class InMemoryReplayCache : public ReplayCache {
    std::int64_t window_secs_;
    std::mutex mu_;
    std::map<std::pair<std::string, std::string>, std::int64_t> seen_;  // (key,nonce) -> expiry

public:
    explicit InMemoryReplayCache(std::int64_t window_secs) : window_secs_(window_secs) {}

    bool check_and_remember(const std::string& key_id, const std::string& nonce,
                            std::int64_t now_unix) override {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = seen_.begin(); it != seen_.end();) {
            if (it->second <= now_unix)
                it = seen_.erase(it);
            else
                ++it;
        }
        auto key = std::make_pair(key_id, nonce);
        if (seen_.count(key) > 0) return false;
        seen_[key] = now_unix + window_secs_;
        return true;
    }

    std::size_t size() {
        std::lock_guard<std::mutex> lk(mu_);
        return seen_.size();
    }
};

}  // namespace sesame
