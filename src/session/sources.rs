use crate::Identity;

/// The parts of an identity only a federated provider can answer for: the roles claim. The
/// OIDC kit implements it.
#[async_trait::async_trait]
pub trait ClaimsSource: Send + Sync {
    /// Fills in what the provider knows about `identity`.
    async fn attach(&self, identity: &mut Identity);
}

/// Verifies a bearer token shaped as a JWT and resolves it to a local account.
#[async_trait::async_trait]
pub trait JwtVerifier: Send + Sync {
    /// The identity the token names, or why it was refused.
    async fn verify_jwt(&self, raw: &str) -> Result<Identity, Box<dyn std::error::Error + Send + Sync>>;
}
