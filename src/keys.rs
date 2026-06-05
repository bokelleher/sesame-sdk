// src/sesame/keys.rs
//
// Key material and the `KeyProvider` extension seam. Spec: ANSI/SCTE 130-9
// (SESAME) draft v0.5 §8.2.5 (key management), §8.3 (channel scope), §8.4
// (separate encryption keys).
//
// This is NOT a KMS. It is a lookup interface plus a static/config-backed
// implementation. Key distribution is out of band (env vars, secrets managers,
// config files) and is an operator responsibility, exactly as §8.2.5 states.
//
// [BO] The handoff's trait keyed both signing and encryption off one `key_id`.
// The paper separates them: X-SESAME-KeyId selects the signing (HMAC) key, while
// X-SESAME-EncKeyId selects the encryption (AEAD) key, and the two namespaces
// rotate independently (§8.4). The trait below reflects that. We also add
// `signing_keys` (plural) for the rotation overlap window (§8.2.5) and
// `is_revoked` for `sesame_key_revoked` (Appendix A.7). See reconciliation item 6.

use std::collections::{HashMap, HashSet};

use crate::tier3_aead::KEY_LEN;

/// An HMAC signing key (any length; HMAC-SHA256 accepts arbitrary key sizes).
#[derive(Clone)]
pub struct HmacKey(pub Vec<u8>);

/// An AES-256 encryption key (exactly 32 bytes).
#[derive(Clone)]
pub struct AeadKey(pub [u8; KEY_LEN]);

/// The set of channels a signing key-id may act on (Tier 2 policy, §8.3).
#[derive(Clone, Default)]
pub struct ChannelScope {
    allow_all: bool,
    channels: HashSet<String>,
}

impl ChannelScope {
    /// A scope permitting only the listed channels.
    pub fn list<I, S>(channels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ChannelScope {
            allow_all: false,
            channels: channels.into_iter().map(Into::into).collect(),
        }
    }

    /// A wildcard scope (e.g. a trusted single-tenant SAS). Use sparingly.
    pub fn all() -> Self {
        ChannelScope {
            allow_all: true,
            channels: HashSet::new(),
        }
    }

    pub fn permits(&self, channel: &str) -> bool {
        self.allow_all || self.channels.contains(channel)
    }
}

/// Lookup seam for SESAME key material and authorization policy.
pub trait KeyProvider: Send + Sync {
    /// All currently-valid signing keys for `key_id`. Returns more than one only
    /// during a rotation overlap window (§8.2.5). Empty ⇒ unknown key-id.
    fn signing_keys(&self, key_id: &str) -> Vec<HmacKey>;

    /// The primary signing key for `key_id` (used when this node signs its own
    /// outbound responses). `None` ⇒ unknown key-id.
    fn primary_signing_key(&self, key_id: &str) -> Option<HmacKey> {
        self.signing_keys(key_id).into_iter().next()
    }

    /// The AEAD (encryption) key for an `enc_key_id` (Tier 3, §8.4). Looked up
    /// in the encryption-key namespace, which is independent of signing keys.
    fn aead_key(&self, enc_key_id: &str) -> Option<AeadKey>;

    /// Whether `key_id` is authorized to act on `channel` (Tier 2, §8.3).
    fn is_authorized(&self, key_id: &str, channel: &str) -> bool;

    /// Whether `key_id` has been explicitly revoked (Appendix A.7
    /// `sesame_key_revoked`). Revocation is immediate, with no grace (§10.1).
    fn is_revoked(&self, key_id: &str) -> bool;
}

// -------------------------------------------------------------------------
// Static / config-backed implementation
// -------------------------------------------------------------------------

#[derive(Default)]
struct SigningEntry {
    keys: Vec<HmacKey>,
    scope: ChannelScope,
    revoked: bool,
}

/// A `KeyProvider` backed by in-memory maps, populated from configuration
/// (env/file) at startup. Suitable as the reference/default provider.
#[derive(Default)]
pub struct StaticKeyProvider {
    signing: HashMap<String, SigningEntry>,
    aead: HashMap<String, AeadKey>,
}

impl StaticKeyProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a signing key-id with a single key and its channel scope.
    pub fn with_signing_key(mut self, key_id: &str, key: HmacKey, scope: ChannelScope) -> Self {
        self.signing.insert(
            key_id.to_string(),
            SigningEntry {
                keys: vec![key],
                scope,
                revoked: false,
            },
        );
        self
    }

    /// Add an additional valid key for an existing key-id (rotation overlap).
    pub fn add_overlap_key(mut self, key_id: &str, key: HmacKey) -> Self {
        self.signing
            .entry(key_id.to_string())
            .or_default()
            .keys
            .push(key);
        self
    }

    /// Mark a key-id revoked.
    pub fn revoke(mut self, key_id: &str) -> Self {
        if let Some(e) = self.signing.get_mut(key_id) {
            e.revoked = true;
        }
        self
    }

    /// Register an encryption key-id (Tier 3, §8.4).
    pub fn with_aead_key(mut self, enc_key_id: &str, key: AeadKey) -> Self {
        self.aead.insert(enc_key_id.to_string(), key);
        self
    }
}

impl KeyProvider for StaticKeyProvider {
    fn signing_keys(&self, key_id: &str) -> Vec<HmacKey> {
        self.signing
            .get(key_id)
            .map(|e| e.keys.clone())
            .unwrap_or_default()
    }

    fn aead_key(&self, enc_key_id: &str) -> Option<AeadKey> {
        self.aead.get(enc_key_id).cloned()
    }

    fn is_authorized(&self, key_id: &str, channel: &str) -> bool {
        self.signing
            .get(key_id)
            .map(|e| !e.revoked && e.scope.permits(channel))
            .unwrap_or(false)
    }

    fn is_revoked(&self, key_id: &str) -> bool {
        self.signing.get(key_id).map(|e| e.revoked).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_and_scope() {
        let p = StaticKeyProvider::new().with_signing_key(
            "sas-east-01",
            HmacKey(b"secret".to_vec()),
            ChannelScope::list(["SportsFeed-East"]),
        );
        assert_eq!(p.signing_keys("sas-east-01").len(), 1);
        assert!(p.signing_keys("nope").is_empty());
        assert!(p.is_authorized("sas-east-01", "SportsFeed-East"));
        assert!(!p.is_authorized("sas-east-01", "PremiumFeed"));
        assert!(!p.is_revoked("sas-east-01"));
    }

    #[test]
    fn revoked_key_not_authorized() {
        let p = StaticKeyProvider::new()
            .with_signing_key("k", HmacKey(b"s".to_vec()), ChannelScope::all())
            .revoke("k");
        assert!(p.is_revoked("k"));
        assert!(!p.is_authorized("k", "anything"));
    }

    #[test]
    fn separate_aead_namespace() {
        let p = StaticKeyProvider::new().with_aead_key("enc-2026q1", AeadKey([9u8; KEY_LEN]));
        assert!(p.aead_key("enc-2026q1").is_some());
        assert!(p.aead_key("sas-east-01").is_none());
    }
}
