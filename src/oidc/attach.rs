use super::Kit;
use crate::session::ClaimsSource;
use crate::{Identity, StoredIdentity};

#[async_trait::async_trait]
impl ClaimsSource for Kit {
    async fn attach(&self, identity: &mut Identity) {
        if !self.config().claims_enabled() {
            return;
        }
        let stored = match self.identity_for(identity.user_id).await {
            Ok(Some(stored)) => stored,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(user_id = identity.user_id, %error, "porte: failed to load claims");
                return;
            }
        };
        identity.roles = stored.roles.clone().unwrap_or_default();
        identity.roles_synced_at = stored.roles_synced_at;
        if !stored.roles_stale(self.now(), self.config().claims_ttl) {
            return;
        }
        match self.refresh_roles(stored.clone()).await {
            Ok(refreshed) => {
                identity.roles = refreshed.roles.unwrap_or_default();
                identity.roles_synced_at = refreshed.roles_synced_at;
            }
            Err(error) => {
                tracing::warn!(user_id = identity.user_id, %error, "porte: role refresh failed, keeping the cached claim");
                let marked =
                    self.inner.identities.mark_roles_synced(&stored.provider, &stored.subject, self.now()).await;
                if let Err(error) = marked {
                    tracing::warn!(%error, "porte: failed to record the refresh attempt");
                }
            }
        }
    }
}

impl Kit {
    async fn refresh_roles(&self, mut stored: StoredIdentity) -> Result<StoredIdentity, String> {
        if stored.tokens.refresh_token.is_empty() {
            return Err("no refresh token".into());
        }
        let valid = !stored.tokens.access_token.is_empty()
            && stored.tokens.expiry.is_none_or(|expiry| expiry - time::Duration::seconds(10) >= self.now());
        if valid {
            return Err("the refresh response carried no id_token".into());
        }
        let grant = self.refresh(&stored.tokens).await?;
        let raw = grant.id_token.ok_or("the refresh response carried no id_token")?;
        let provider = self.provider().ok_or("OIDC is not configured")?;
        let token = provider.id_tokens.verify(&raw).await.map_err(|error| error.to_string())?;
        let claims = self.claims_from(&token.subject, &token.claims, true)?;
        stored.tokens = grant.tokens;
        stored.roles = claims.roles;
        stored.roles_synced_at = Some(self.now());
        self.inner.identities.save(&stored).await.map_err(|error| error.to_string())?;
        Ok(stored)
    }
}
