//! Offline verification of RS256 access tokens from the issuer, a port of Go `porte/oidc/jwt`.
//!
//! Discovery runs once at [`Verifier::new`]; the JWKS is cached for an hour, refetched once on
//! an unknown `kid` and at most every 30 s for that reason, so forged kids cost one fetch.

pub(crate) mod claims;
pub(crate) mod discover;
pub(crate) mod keys;

use std::time::Duration;

pub use crate::jwt_error::JwtError;
pub use claims::{Claims, Profile};

use crate::Clock;
use crate::http_client::HttpClient;
use keys::KeyCache;

/// How long fetched keys are trusted.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Clock skew forgiven on `exp`, `nbf` and `iat`.
pub const LEEWAY: Duration = Duration::from_secs(30);

/// What a [`Verifier`] checks a token against.
#[derive(Clone)]
pub struct Config {
    /// The `iss` every token must carry, byte for byte.
    pub issuer: String,
    /// The `aud` a token must name.
    pub audience: String,
    /// Further audiences accepted through the same keys. Empty entries are ignored.
    pub extra_audiences: Vec<String>,
    /// Zero means [`DEFAULT_CACHE_TTL`].
    pub cache_ttl: Duration,
    /// The outbound HTTP.
    pub http: HttpClient,
    /// `None` means the wall clock.
    pub now: Option<Clock>,
}

/// Verifies RS256 JWTs against the issuer's JWKS.
pub struct Verifier {
    cfg: Config,
    now: Clock,
    keys: KeyCache,
}

impl Verifier {
    /// Runs discovery against `cfg.issuer` and fails when it does not answer, names another
    /// issuer, or advertises no `jwks_uri`.
    pub async fn new(cfg: Config) -> Result<Verifier, JwtError> {
        if cfg.issuer.is_empty() || cfg.audience.is_empty() {
            return Err(JwtError::Config("an issuer and an audience are required".into()));
        }
        let jwks_uri = discover::jwks_uri(&cfg.http, &cfg.issuer).await?;
        let now = cfg.now.clone().unwrap_or_else(crate::system_clock);
        let ttl = if cfg.cache_ttl.is_zero() { DEFAULT_CACHE_TTL } else { cfg.cache_ttl };
        let keys = KeyCache::new(cfg.http.clone(), jwks_uri, ttl, now.clone());
        Ok(Verifier { cfg, now, keys })
    }

    /// The claims of a valid token, or why it was refused.
    pub async fn verify(&self, raw: &str) -> Result<Claims, JwtError> {
        let token = crate::jose::split(raw)?;
        if token.header.alg != "RS256" {
            return Err(JwtError::Algorithm(token.header.alg));
        }
        let key = self.keys.key(&token.header.kid).await?;
        if !crate::rs256::verify(&key, &token.signing_input, &token.signature) {
            return Err(JwtError::Signature);
        }
        let payload = claims::parse(&token.payload)?;
        if payload.issuer() != self.cfg.issuer {
            return Err(JwtError::Issuer(payload.issuer().to_owned()));
        }
        if !self.audience_accepted(&payload.audience) {
            return Err(JwtError::Audience);
        }
        payload.within_validity((self.now)())?;
        Ok(payload.into_claims())
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    fn audience_accepted(&self, audience: &[String]) -> bool {
        let extra = self.cfg.extra_audiences.iter().filter(|value| !value.is_empty());
        std::iter::once(&self.cfg.audience).chain(extra).any(|wanted| audience.contains(wanted))
    }
}
