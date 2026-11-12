use std::sync::Arc;

use super::Kit;
use super::bearer::resolve_bearer;
use super::failure::caller_error;
use crate::jwt::Claims as TokenClaims;
use crate::{Claims, Identity, StoreError, SubjectErased, TokenSet};

/// Why [`Kit::provision_bearer`] did not return an account.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// The token cannot vouch for an account: no email, an unverified one, no roles when a
    /// roles scope is configured, OIDC off, or the app's store refused it.
    #[error("porte/oidc: the account cannot be provisioned from this token: {0}")]
    Refused(String),
    /// The identity belongs to a person the app already erased ([`crate::SubjectErased`]). A
    /// refusal as [`ProvisionError::Refused`] is: mcpauth answers an invalid token.
    #[error("porte/oidc: the account cannot be provisioned from this token: this account was deleted")]
    Erased,
    /// A store failed. Not the token's fault.
    #[error("porte/oidc: provisioning failed: {0}")]
    Store(String),
}

impl Kit {
    /// Creates the local account for a verified bearer subject through the login callback's own
    /// write path, or returns the existing one untouched. Concurrent first calls for one subject
    /// share one provisioning.
    pub async fn provision_bearer(&self, token: &TokenClaims) -> Result<Identity, ProvisionError> {
        if !self.enabled() {
            return Err(ProvisionError::Refused("OIDC is not configured".into()));
        }
        if let Some(found) = self.existing(token).await? {
            return Ok(found);
        }
        let gate = self.gate(&token.subject).await;
        let _held = gate.lock().await;
        if let Some(found) = self.existing(token).await? {
            return Ok(found);
        }
        let claims = self.claims_from_access_token(token)?;
        self.persist(claims, TokenSet::default()).await.map_err(|error| {
            match (SubjectErased::caused(&error), caller_error(&error)) {
                (true, _) => ProvisionError::Erased,
                (false, true) => ProvisionError::Refused(error.message),
                (false, false) => ProvisionError::Store(error.to_string()),
            }
        })?;
        tracing::info!(subject = %token.subject, "porte: provisioned an account from a bearer token");
        self.existing(token).await?.ok_or_else(|| ProvisionError::Store("the provisioned account vanished".into()))
    }

    async fn existing(&self, token: &TokenClaims) -> Result<Option<Identity>, ProvisionError> {
        match resolve_bearer(self.inner.identities.as_ref(), &self.config().issuer, token).await {
            Ok(identity) => Ok(Some(identity)),
            Err(StoreError::NotFound) => Ok(None),
            Err(error) => Err(ProvisionError::Store(error.to_string())),
        }
    }

    async fn gate(&self, subject: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.inner.provisioning.lock().await;
        gates.retain(|_, gate| Arc::strong_count(gate) > 1);
        gates.entry(subject.to_owned()).or_default().clone()
    }

    fn claims_from_access_token(&self, token: &TokenClaims) -> Result<Claims, ProvisionError> {
        let mut claims = Claims {
            provider: self.config().issuer.clone(),
            subject: token.subject.clone(),
            email: super::claims::normalize_email(&token.email),
            email_verified: self.email_trusted(token.profile.email_verified),
            name: token.name.clone(),
            preferred_username: token.profile.preferred_username.clone(),
            picture: token.profile.picture.clone(),
            locale: super::claims::locale_claim(Some(&serde_json::Value::from(token.profile.locale.clone()))),
            ..Claims::default()
        };
        if claims.email.is_empty() {
            return Err(ProvisionError::Refused("the token carries no email".into()));
        }
        if !claims.email_verified {
            return Err(ProvisionError::Refused("the token's email is not verified".into()));
        }
        if self.config().claims_enabled() {
            let scope = &self.config().claims_scope;
            let roles = token.roles.clone();
            claims.roles = Some(roles.ok_or_else(|| {
                ProvisionError::Refused(format!("scope {scope:?} is configured but the token carries no roles"))
            })?);
        }
        Ok(claims)
    }
}
