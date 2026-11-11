use std::sync::Arc;
use std::time::Duration;

use super::DEFAULT_MARGIN;
use crate::http_client::HttpClient;
use crate::{Clock, IdentityStore};

/// What a token is exchanged for: the downstream app's audience (its Registre client id, or the
/// name Registre's seed grants) and the scopes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Target {
    /// The downstream app's audience.
    pub audience: String,
    /// The scopes asked for.
    pub scopes: Vec<String>,
}

impl Target {
    /// A target for `audience` with `scopes`.
    pub fn new(audience: impl Into<String>, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Target { audience: audience.into(), scopes: scopes.into_iter().map(Into::into).collect() }
    }

    pub(super) fn key(&self) -> String {
        let mut scopes = self.scopes.clone();
        scopes.sort();
        format!("{}\0{}", self.audience, scopes.join(" "))
    }
}

/// Wires an [`Exchanger`]. `issuer` must be the value the `oidc` feature was configured with,
/// because it is also the provider `porte_identities` rows are filed under.
#[derive(Clone)]
pub struct Config {
    /// `OIDC_ISSUER`.
    pub issuer: String,
    /// `OIDC_CLIENT_ID`.
    pub client_id: String,
    /// `OIDC_CLIENT_SECRET`.
    pub client_secret: String,
    /// Reads a user's identities and writes a rotated refresh token back. `pg::Store` built with
    /// a token sealer seals them.
    pub identities: Arc<dyn IdentityStore>,
    /// Calls Registre.
    pub http: HttpClient,
    /// How long before its expiry a token stops being reused. Zero means [`DEFAULT_MARGIN`].
    pub margin: Duration,
    /// The clock.
    pub clock: Clock,
}

impl Config {
    /// A config with the default client, margin and clock.
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        identities: Arc<dyn IdentityStore>,
    ) -> Self {
        Config {
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            identities,
            http: HttpClient::new(),
            margin: DEFAULT_MARGIN,
            clock: crate::system_clock(),
        }
    }

    /// [`Config::new`] with the issuer and client credentials of porte's own config.
    pub fn from_porte(config: &crate::Config, identities: Arc<dyn IdentityStore>) -> Self {
        Config::new(&config.issuer, &config.client_id, &config.client_secret, identities)
    }
}
