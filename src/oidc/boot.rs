use std::sync::Arc;

use super::bearer::BearerVerifier;
use super::id_token::IdTokenVerifier;
use crate::http_client::HttpClient;
use crate::jwt::discover::{Discovery, document};
use crate::session::Manager;
use crate::{Clock, Config, ConfigError, IdentityStore};

pub(crate) struct Provider {
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) userinfo_endpoint: String,
    pub(crate) id_tokens: IdTokenVerifier,
}

pub(crate) type Armed = (Option<Provider>, Option<Arc<BearerVerifier>>);

pub(crate) fn agrees_with(kit: &Config, manager: &Config) -> Result<(), ConfigError> {
    let kit = kit.resolved();
    let pairs = [
        ("OIDC_REDIRECT_URL", kit.redirect_url.clone(), manager.redirect_url.clone()),
        ("OIDC_SUCCESS_URL", kit.success_url.clone(), manager.success_url.clone()),
        ("SessionTTL", format!("{:?}", kit.session_ttl), format!("{:?}", manager.session_ttl)),
        ("SessionIdleTTL", format!("{:?}", kit.idle_timeout()), format!("{:?}", manager.idle_timeout())),
    ];
    match pairs.into_iter().find(|(_, a, b)| a != b) {
        Some((name, a, b)) => Err(ConfigError::new(format!(
            "the kit and its session manager disagree about {name} ({a:?} vs {b:?}) — build both from the same porte::Config"
        ))),
        None => Ok(()),
    }
}

pub(crate) async fn arm(
    cfg: &Config,
    http: &HttpClient,
    identities: &Arc<dyn IdentityStore>,
    sessions: &Manager,
    now: &Clock,
) -> Result<Armed, ConfigError> {
    let metadata = discover(cfg, http).await?;
    guard_claims_scope(cfg, &metadata)?;
    let provider = Provider {
        id_tokens: IdTokenVerifier::new(http.clone(), metadata.jwks_uri, &cfg.issuer, &cfg.client_id, now.clone()),
        authorization_endpoint: metadata.authorization_endpoint,
        token_endpoint: metadata.token_endpoint,
        userinfo_endpoint: metadata.userinfo_endpoint,
    };
    if !cfg.machine_audience.is_empty() {
        let machine = BearerVerifier::new(cfg, &cfg.machine_audience, http, identities, now).await?;
        sessions.with_jwt(Arc::new(machine));
    }
    let cli = match cfg.cli_audience.is_empty() {
        true => None,
        false => Some(Arc::new(BearerVerifier::new(cfg, &cfg.cli_audience, http, identities, now).await?)),
    };
    Ok((Some(provider), cli))
}

/// Fetches discovery and holds it to what go-oidc's `NewProvider` requires: the issuer byte for
/// byte, an authorization endpoint and a JWKS URI.
async fn discover(cfg: &Config, http: &HttpClient) -> Result<Discovery, ConfigError> {
    let failed = |error: String| ConfigError::new(format!("discovery failed for {}: {error}", cfg.issuer));
    let metadata = document(http, &cfg.issuer).await.map_err(failed)?;
    if metadata.issuer != cfg.issuer {
        return Err(failed(format!("the provider publishes issuer {:?}", metadata.issuer)));
    }
    if metadata.authorization_endpoint.is_empty() || metadata.jwks_uri.is_empty() {
        return Err(failed("the document names no authorization_endpoint or jwks_uri".into()));
    }
    Ok(metadata)
}

fn guard_claims_scope(cfg: &Config, metadata: &Discovery) -> Result<(), ConfigError> {
    if !cfg.claims_enabled() {
        return Ok(());
    }
    match &metadata.scopes_supported {
        None => {
            tracing::warn!(scope = %cfg.claims_scope, "porte: provider advertises no scopes_supported, cannot verify the roles scope");
            Ok(())
        }
        Some(scopes) if scopes.is_empty() || scopes.contains(&cfg.claims_scope) => Ok(()),
        Some(_) => Err(ConfigError::new(format!(
            "the roles scope {:?} is not offered by {} — attach the scope mapping to the provider, or unset it here; leaving it half-configured makes every role check deny silently",
            cfg.claims_scope, cfg.issuer
        ))),
    }
}
