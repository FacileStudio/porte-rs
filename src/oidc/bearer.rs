use std::sync::Arc;

use crate::http_client::HttpClient;
use crate::jwt::{self, Claims as TokenClaims, Verifier};
use crate::session::JwtVerifier;
use crate::{Clock, Config, ConfigError, Identity, IdentityStore, StoreError};

/// Verifies bearer JWTs for one audience and resolves them to local accounts.
pub(crate) struct BearerVerifier {
    tokens: Verifier,
    identities: Arc<dyn IdentityStore>,
    issuer: String,
}

impl BearerVerifier {
    pub(crate) async fn new(
        cfg: &Config,
        audience: &str,
        http: &HttpClient,
        identities: &Arc<dyn IdentityStore>,
        now: &Clock,
    ) -> Result<Self, ConfigError> {
        let config = jwt::Config {
            issuer: cfg.issuer.clone(),
            audience: audience.to_owned(),
            extra_audiences: Vec::new(),
            cache_ttl: std::time::Duration::ZERO,
            http: http.clone(),
            now: Some(now.clone()),
        };
        let tokens = Verifier::new(config).await.map_err(|error| {
            ConfigError::new(format!(
                "bearer-token verification for audience {audience:?} failed to configure: {error}"
            ))
        })?;
        Ok(BearerVerifier { tokens, identities: identities.clone(), issuer: cfg.issuer.clone() })
    }
}

#[async_trait::async_trait]
impl JwtVerifier for BearerVerifier {
    async fn verify_jwt(&self, raw: &str) -> Result<Identity, Box<dyn std::error::Error + Send + Sync>> {
        let claims = self.tokens.verify(raw).await?;
        Ok(resolve_bearer(self.identities.as_ref(), &self.issuer, &claims).await?)
    }
}

/// The `(iss, sub)` to account mapping of the bearer path: the identity row under `issuer` and
/// the token's subject. No email fallback. An unknown subject is [`StoreError::NotFound`]; a
/// token without a subject, or a row naming no account, is [`StoreError::Other`].
pub async fn resolve_bearer(
    identities: &dyn IdentityStore,
    issuer: &str,
    claims: &TokenClaims,
) -> Result<Identity, StoreError> {
    if claims.subject.is_empty() {
        return Err(StoreError::other("porte/oidc: the token asserts no subject"));
    }
    let stored = identities.find(issuer, &claims.subject).await?;
    if stored.user_id == 0 {
        return Err(StoreError::other(format!(
            "porte/oidc: the identity row for {:?} names no account",
            claims.subject
        )));
    }
    Ok(Identity {
        user_id: stored.user_id,
        subject: claims.subject.clone(),
        email: claims.email.clone(),
        name: claims.name.clone(),
        roles: claims.roles.clone().unwrap_or_default(),
        scopes: claims.scopes.clone(),
        actor: claims.actor.clone(),
        ..Identity::default()
    })
}
