package sesame

// ChannelScope is the set of channels a signing key-id may act on (Tier 2).
type ChannelScope struct {
	allowAll bool
	channels map[string]bool
}

// AllChannels returns a wildcard scope. Use sparingly.
func AllChannels() ChannelScope { return ChannelScope{allowAll: true} }

// ListChannels returns a scope permitting only the listed channels.
func ListChannels(channels ...string) ChannelScope {
	m := make(map[string]bool, len(channels))
	for _, c := range channels {
		m[c] = true
	}
	return ChannelScope{channels: m}
}

// Permits reports whether the scope allows the channel.
func (s ChannelScope) Permits(channel string) bool {
	return s.allowAll || s.channels[channel]
}

// KeyProvider is the lookup/authorization seam for SESAME key material.
type KeyProvider interface {
	// SigningKeys returns all currently-valid signing keys for keyID (more than
	// one only during a rotation overlap). nil/empty means unknown.
	SigningKeys(keyID string) [][]byte
	// PrimarySigningKey returns the primary signing key for keyID.
	PrimarySigningKey(keyID string) ([]byte, bool)
	// AEADKey returns the encryption key for encKeyID (separate namespace).
	AEADKey(encKeyID string) ([]byte, bool)
	// IsAuthorized reports whether keyID may act on channel (Tier 2).
	IsAuthorized(keyID, channel string) bool
	// IsRevoked reports whether keyID is explicitly revoked.
	IsRevoked(keyID string) bool
}

type signingEntry struct {
	keys    [][]byte
	scope   ChannelScope
	revoked bool
}

// StaticKeyProvider is an in-memory, config-backed reference KeyProvider.
type StaticKeyProvider struct {
	signing map[string]*signingEntry
	aead    map[string][]byte
}

// NewStaticKeyProvider returns an empty provider.
func NewStaticKeyProvider() *StaticKeyProvider {
	return &StaticKeyProvider{
		signing: map[string]*signingEntry{},
		aead:    map[string][]byte{},
	}
}

func (p *StaticKeyProvider) WithSigningKey(keyID string, key []byte, scope ChannelScope) *StaticKeyProvider {
	p.signing[keyID] = &signingEntry{keys: [][]byte{key}, scope: scope}
	return p
}

func (p *StaticKeyProvider) AddOverlapKey(keyID string, key []byte) *StaticKeyProvider {
	if e := p.signing[keyID]; e != nil {
		e.keys = append(e.keys, key)
	}
	return p
}

func (p *StaticKeyProvider) Revoke(keyID string) *StaticKeyProvider {
	if e := p.signing[keyID]; e != nil {
		e.revoked = true
	}
	return p
}

func (p *StaticKeyProvider) WithAEADKey(encKeyID string, key []byte) *StaticKeyProvider {
	p.aead[encKeyID] = key
	return p
}

func (p *StaticKeyProvider) SigningKeys(keyID string) [][]byte {
	if e := p.signing[keyID]; e != nil {
		return e.keys
	}
	return nil
}

func (p *StaticKeyProvider) PrimarySigningKey(keyID string) ([]byte, bool) {
	if e := p.signing[keyID]; e != nil && len(e.keys) > 0 {
		return e.keys[0], true
	}
	return nil, false
}

func (p *StaticKeyProvider) AEADKey(encKeyID string) ([]byte, bool) {
	k, ok := p.aead[encKeyID]
	return k, ok
}

func (p *StaticKeyProvider) IsAuthorized(keyID, channel string) bool {
	e := p.signing[keyID]
	return e != nil && !e.revoked && e.scope.Permits(channel)
}

func (p *StaticKeyProvider) IsRevoked(keyID string) bool {
	e := p.signing[keyID]
	return e != nil && e.revoked
}
