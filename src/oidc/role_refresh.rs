use super::Kit;
use super::token_failure::TokenFailure;
use super::tokens::Grant;
use crate::{StoredIdentity, secure_compare};

impl Kit {
    pub(super) async fn refresh_roles(&self, stored: StoredIdentity) -> Result<StoredIdentity, TokenFailure> {
        match self.refresh(&stored.tokens).await {
            Ok(grant) => self.keep_grant(stored, grant).await,
            Err(TokenFailure::Refused(reason)) => {
                let Some(latest) = self.rotated(&stored).await else { return Err(TokenFailure::Refused(reason)) };
                let grant = self.refresh(&latest.tokens).await?;
                self.keep_grant(latest, grant).await
            }
            Err(failure) => Err(failure),
        }
    }

    /// The identity as stored now, when its refresh token is no longer the refused one: another
    /// replica or the token exchange rotated it in the meantime.
    async fn rotated(&self, refused: &StoredIdentity) -> Option<StoredIdentity> {
        let latest = self.stored_roles(refused.user_id).await?;
        let changed = latest.tokens.refresh_token != refused.tokens.refresh_token;
        (changed && !latest.tokens.refresh_token.is_empty()).then_some(latest)
    }

    /// Saves the rotated tokens whatever the ID token says: the old refresh token is spent. A
    /// response without an ID token proves the grant is alive and keeps the cached roles.
    async fn keep_grant(&self, mut stored: StoredIdentity, grant: Grant) -> Result<StoredIdentity, TokenFailure> {
        stored.tokens = grant.tokens;
        let roles = match grant.id_token {
            Some(raw) => self.granted_roles(&raw, &stored.subject).await,
            None => Ok(stored.roles.clone()),
        };
        if let Ok(roles) = &roles {
            stored.roles = roles.clone();
            stored.roles_synced_at = Some(self.now());
        }
        self.inner.identities.save(&stored).await.map_err(|error| error.to_string())?;
        roles.map(|_| stored).map_err(TokenFailure::Other)
    }

    async fn granted_roles(&self, raw: &str, subject: &str) -> Result<Option<Vec<String>>, String> {
        let provider = self.provider().ok_or("OIDC is not configured")?;
        let token = provider.id_tokens.verify(raw).await.map_err(|error| error.to_string())?;
        if !secure_compare(&token.subject, subject) {
            return Err("the refreshed ID token names another subject".into());
        }
        Ok(self.claims_from(&token.subject, &token.claims, true)?.roles)
    }
}
