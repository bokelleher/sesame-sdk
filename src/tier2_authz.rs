// src/sesame/tier2_authz.rs
//
// Tier 2, Channel-scoped authorization. Spec: ANSI/SCTE 130-9 (SESAME)
// draft v0.5 §8.3.
//
// The X-SESAME-Scope header declares the intended channel as `channel=<id>`.
// It is bound into the signature (canonical.rs) so it cannot be swapped without
// invalidating Tier 1. Here we (a) parse the declared channel, (b) confirm it
// matches the channel the request is actually targeting, and (c) confirm the
// authenticated key-id is permitted that channel.

use crate::keys::KeyProvider;
use crate::message::SesameError;

/// Parse `channel=<id>` from an X-SESAME-Scope value. Returns the channel id.
pub fn parse_scope_channel(scope: &str) -> Option<&str> {
    scope.strip_prefix("channel=").map(str::trim)
}

/// Enforce Tier 2 for an authenticated request.
///
/// * `scope`, the X-SESAME-Scope header value (`channel=<id>`).
/// * `target_channel`, the channel the request is actually addressing (URL
///   path/query or, for rust-pois, the resolved channel). If present, it MUST
///   equal the declared scope channel, else `ScopeDenied`, this prevents a
///   request signed for channel A from being directed at channel B.
/// * The authenticated `key_id` must be authorized for the channel by policy.
pub fn authorize(
    provider: &dyn KeyProvider,
    key_id: &str,
    scope: &str,
    target_channel: Option<&str>,
) -> Result<String, SesameError> {
    let declared = parse_scope_channel(scope).ok_or(SesameError::ScopeDenied)?;

    if let Some(target) = target_channel {
        if !declared.eq(target) {
            return Err(SesameError::ScopeDenied);
        }
    }

    if provider.is_authorized(key_id, declared) {
        Ok(declared.to_string())
    } else {
        Err(SesameError::ScopeDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{ChannelScope, HmacKey, StaticKeyProvider};

    fn provider() -> StaticKeyProvider {
        StaticKeyProvider::new().with_signing_key(
            "sas-east-01",
            HmacKey(b"k".to_vec()),
            ChannelScope::list(["SportsFeed-East"]),
        )
    }

    #[test]
    fn parse_scope() {
        assert_eq!(
            parse_scope_channel("channel=SportsFeed-East"),
            Some("SportsFeed-East")
        );
        assert_eq!(parse_scope_channel("nope"), None);
    }

    #[test]
    fn authorized_channel_accepted() {
        let p = provider();
        assert_eq!(
            authorize(
                &p,
                "sas-east-01",
                "channel=SportsFeed-East",
                Some("SportsFeed-East")
            ),
            Ok("SportsFeed-East".to_string())
        );
    }

    #[test]
    fn unauthorized_channel_denied() {
        let p = provider();
        assert_eq!(
            authorize(
                &p,
                "sas-east-01",
                "channel=PremiumFeed",
                Some("PremiumFeed")
            ),
            Err(SesameError::ScopeDenied)
        );
    }

    #[test]
    fn scope_target_mismatch_denied() {
        // Signed scope says SportsFeed-East but request targets PremiumFeed.
        let p = provider();
        assert_eq!(
            authorize(
                &p,
                "sas-east-01",
                "channel=SportsFeed-East",
                Some("PremiumFeed")
            ),
            Err(SesameError::ScopeDenied)
        );
    }
}
