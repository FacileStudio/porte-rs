use url::Url;

use super::Config;
use crate::ConfigError;

pub(crate) fn validate(cfg: &Config) -> Result<(), ConfigError> {
    if cfg.issuer.is_empty() {
        return Err(ConfigError::new("mcpauth: an issuer and an identity store are required"));
    }
    validate_provision(cfg)?;
    let prefix = &cfg.scope_prefix;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err(ConfigError::new(format!("mcpauth: scope prefix {prefix:?} is not a lower-case app name")));
    }
    let resource = Url::parse(&cfg.resource).ok();
    let valid = resource.is_some_and(|url| {
        matches!(url.scheme(), "http" | "https") && url.has_host() && url.query().is_none() && url.fragment().is_none()
    });
    if !valid {
        return Err(ConfigError::new(format!(
            "mcpauth: resource {:?} is not an absolute URI without query or fragment",
            cfg.resource
        )));
    }
    Ok(())
}

fn validate_provision(cfg: &Config) -> Result<(), ConfigError> {
    if !cfg.provision {
        return Ok(());
    }
    match cfg.accounts.as_ref().map(|kit| kit.config().issuer.clone()) {
        None => Err(ConfigError::new("mcpauth: Provision needs Accounts, the app's porte OIDC kit")),
        Some(issuer) if issuer != cfg.issuer => Err(ConfigError::new(format!(
            "mcpauth: Accounts files identities under {issuer:?}, not the issuer {:?}",
            cfg.issuer
        ))),
        Some(_) => Ok(()),
    }
}
