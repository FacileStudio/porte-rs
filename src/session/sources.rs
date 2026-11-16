use crate::Identity;

/// The parts of an identity only a federated provider can answer for: the roles claim. The
/// OIDC kit implements it.
#[async_trait::async_trait]
pub trait ClaimsSource: Send + Sync {
    /// Fills in what the provider knows about `identity`.
    async fn attach(&self, identity: &mut Identity);

    /// Fills in `identity` as [`ClaimsSource::attach`] does and answers whether its sign-in
    /// still stands. `false` means the provider withdrew the grant: the manager refuses the
    /// request and drops the login, and lets a named API token through without roles. The
    /// default attaches and admits.
    async fn admit(&self, identity: &mut Identity) -> bool {
        self.attach(identity).await;
        true
    }
}

/// Verifies a bearer token shaped as a JWT and resolves it to a local account.
#[async_trait::async_trait]
pub trait JwtVerifier: Send + Sync {
    /// The identity the token names, or why it was refused.
    async fn verify_jwt(&self, raw: &str) -> Result<Identity, Box<dyn std::error::Error + Send + Sync>>;
}
