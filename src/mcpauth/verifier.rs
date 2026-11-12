use std::sync::Arc;
use std::time::Duration;

use super::TokenInfo;
use super::config::validate;
use super::scopes::{scopes_for, with_implied_read};
use crate::http_client::HttpClient;
use crate::jwt::{self, Claims};
use crate::oidc::{Kit, ProvisionError, resolve_bearer};
use crate::{ConfigError, Identity, IdentityStore, StoreError};

/// What a [`Verifier`] checks tokens against.
#[derive(Clone)]
pub struct Config {
    /// The issuer, byte for byte.
    pub issuer: String,
    /// The resource the token's `aud` must name: `https://<app>.facile.studio/mcp`.
    pub resource: String,
    /// The app's lower-case name: the scopes are `<prefix>.read` and `<prefix>.write`.
    pub scope_prefix: String,
    /// The app's client id, accepted as `aud` on delegated tokens only. Empty accepts none.
    pub audience: String,
    /// Where `(iss, sub)` resolves to an account.
    pub identities: Arc<dyn IdentityStore>,
    /// Creates the account on a first call. Needs `accounts`.
    pub provision: bool,
    /// The app's OIDC kit, which provisions through the login's own write path.
    pub accounts: Option<Kit>,
    /// The outbound HTTP.
    pub http: HttpClient,
}

/// Why a token did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Any refusal of the token itself: 401.
    #[error("invalid token")]
    InvalidToken,
    /// The JWKS or the identity store could not be reached: 500.
    #[error("token verification is unavailable")]
    Unavailable,
}

/// Verifies MCP tokens offline and resolves them to local accounts.
pub struct Verifier {
    cfg: Config,
    tokens: jwt::Verifier,
}

impl Verifier {
    /// Validates the config and runs discovery against the issuer.
    pub async fn new(cfg: Config) -> Result<Verifier, ConfigError> {
        validate(&cfg)?;
        let tokens = jwt::Verifier::new(jwt::Config {
            issuer: cfg.issuer.clone(),
            audience: cfg.resource.clone(),
            extra_audiences: vec![cfg.audience.clone()],
            cache_ttl: Duration::ZERO,
            http: cfg.http.clone(),
            now: None,
        })
        .await
        .map_err(|error| ConfigError::new(format!("mcpauth: {error}")))?;
        Ok(Verifier { cfg, tokens })
    }

    /// The grant a token carries, or why it was refused.
    pub async fn verify(&self, raw: &str) -> Result<TokenInfo, VerifyError> {
        let claims = self.claims(raw).await?;
        let identity = self.account(&claims).await?;
        Ok(TokenInfo {
            user_id: identity.user_id.to_string(),
            scopes: with_implied_read(claims.scopes, &scopes_for(&self.cfg.scope_prefix)),
            expiration: claims.expires_at,
            client_id: claims.client_id,
            actor: claims.actor,
            subject: claims.subject,
        })
    }

    async fn claims(&self, raw: &str) -> Result<Claims, VerifyError> {
        let claims = match self.tokens.verify(raw).await {
            Ok(claims) => claims,
            Err(error) if error.is_invalid() => return Err(refuse(&error.to_string())),
            Err(error) => return Err(unavailable(&error.to_string())),
        };
        if !claims.audience.contains(&self.cfg.resource) && claims.actor.is_empty() {
            return Err(refuse("the app audience is accepted on delegated tokens only"));
        }
        Ok(claims)
    }

    async fn account(&self, claims: &Claims) -> Result<Identity, VerifyError> {
        match resolve_bearer(self.cfg.identities.as_ref(), &self.cfg.issuer, claims).await {
            Ok(identity) => Ok(identity),
            Err(StoreError::NotFound) if self.cfg.provision => self.provision(claims).await,
            Err(StoreError::NotFound) => Err(refuse("no local account")),
            Err(error) if claims.subject.is_empty() => Err(refuse(&error.to_string())),
            Err(error) => Err(unavailable(&error.to_string())),
        }
    }

    async fn provision(&self, claims: &Claims) -> Result<Identity, VerifyError> {
        let kit = self.cfg.accounts.as_ref().ok_or(VerifyError::Unavailable)?;
        match kit.provision_bearer(claims).await {
            Ok(identity) => Ok(identity),
            Err(ProvisionError::Refused(reason)) => Err(refuse(&reason)),
            Err(error @ ProvisionError::Erased) => Err(refuse(&error.to_string())),
            Err(ProvisionError::Store(reason)) => Err(unavailable(&reason)),
        }
    }
}

fn refuse(reason: &str) -> VerifyError {
    tracing::debug!(reason, "porte/mcpauth: bearer token refused");
    VerifyError::InvalidToken
}

fn unavailable(cause: &str) -> VerifyError {
    tracing::error!(cause, "porte/mcpauth: bearer token could not be checked");
    VerifyError::Unavailable
}
