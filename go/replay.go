package sesame

import "sync"

// ReplayCache is the replay-protection seam. CheckAndRemember atomically tests
// for a previously seen (keyID, nonce) within the window and records it if new.
type ReplayCache interface {
	// CheckAndRemember returns true if fresh (and records it), false if seen.
	CheckAndRemember(keyID, nonce string, nowUnix int64) bool
}

// InMemoryReplayCache is a per-process TTL cache bounded by the window.
type InMemoryReplayCache struct {
	windowSecs int64
	mu         sync.Mutex
	seen       map[[2]string]int64 // (keyID, nonce) -> expiry unix secs
}

// NewInMemoryReplayCache returns a cache with the given window in seconds.
func NewInMemoryReplayCache(windowSecs int64) *InMemoryReplayCache {
	return &InMemoryReplayCache{windowSecs: windowSecs, seen: map[[2]string]int64{}}
}

func (c *InMemoryReplayCache) CheckAndRemember(keyID, nonce string, nowUnix int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.seen {
		if exp <= nowUnix {
			delete(c.seen, k)
		}
	}
	key := [2]string{keyID, nonce}
	if _, ok := c.seen[key]; ok {
		return false
	}
	c.seen[key] = nowUnix + c.windowSecs
	return true
}

// Len returns the number of live entries.
func (c *InMemoryReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
