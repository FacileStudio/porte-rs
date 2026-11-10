use std::sync::Arc;

use openidconnect::IssuerUrl;
use openidconnect::core::CoreProviderMetadata;

use super::bearer::BearerVerifier;
use super::id_token::IdTokenVerifier;
use crate::http_client::HttpClient;
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
    let jwks_uri = metadata.jwks_uri().url().to_string();
    let provider = Provider {
        authorization_endpoint: metadata.authorization_endpoint().url().to_string(),
        token_endpoint: metadata.token_endpoint().map(|url| url.url().to_string()).unwrap_or_default(),
        userinfo_endpoint: metadata.userinfo_endpoint().map(|url| url.url().to_string()).unwrap_or_default(),
        id_tokens: IdTokenVerifier::new(http.clone(), jwks_uri, &cfg.issuer, &cfg.client_id, now.clone()),
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

async fn discover(cfg: &Config, http: &HttpClient) -> Result<CoreProviderMetadata, ConfigError> {
    let failed = |error: String| ConfigError::new(format!("discovery failed for {}: {error}", cfg.issuer));
    let issuer = IssuerUrl::new(cfg.issuer.clone()).map_err(|error| failed(error.to_string()))?;
    CoreProviderMetadata::discover_async(issuer, http).await.map_err(|error| failed(error.to_string()))
}

fn guard_claims_scope(cfg: &Config, metadata: &CoreProviderMetadata) -> Result<(), ConfigError> {
    if !cfg.claims_enabled() {
        return Ok(());
    }
    let offered = metadata.scopes_supported().map(|scopes| scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    match offered {
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
