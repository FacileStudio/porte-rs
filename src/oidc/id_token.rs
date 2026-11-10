use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::Clock;
use crate::http_client::HttpClient;
use crate::jwt::claims::audience;
use crate::jwt::keys::KeyCache;
use crate::jwt::segments::{decode_object, split};

const NBF_LEEWAY: Duration = Duration::from_secs(5 * 60);

/// Why an ID token or a logout token was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("porte/oidc: {0}")]
pub struct IdTokenError(pub String);

/// A verified ID token: the subject, the nonce and the whole payload.
#[derive(Debug, Clone)]
pub struct IdToken {
    /// `sub`.
    pub subject: String,
    /// `nonce`.
    pub nonce: String,
    /// The payload as JSON.
    pub claims: Value,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Registered {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Value>,
    exp: Option<Value>,
    nbf: Option<Value>,
    nonce: Option<String>,
}

pub(crate) struct IdTokenVerifier {
    keys: KeyCache,
    issuer: String,
    client_id: String,
    now: Clock,
}

impl IdTokenVerifier {
    pub(crate) fn new(http: HttpClient, jwks_uri: String, issuer: &str, client_id: &str, now: Clock) -> Self {
        let keys = KeyCache::new(http, jwks_uri, crate::jwt::DEFAULT_CACHE_TTL, now.clone());
        IdTokenVerifier { keys, issuer: issuer.to_owned(), client_id: client_id.to_owned(), now }
    }

    /// Verifies as go-oidc's `IDTokenVerifier` does: RS256 only, signature first, then `iss`
    /// byte for byte, `aud` naming the client, `exp` strictly ahead, `nbf` with 5 minutes of
    /// leeway. A missing `sub` is accepted here; the caller decides.
    pub(crate) async fn verify(&self, raw: &str) -> Result<IdToken, IdTokenError> {
        let refuse = |reason: &str| IdTokenError(reason.to_owned());
        let token = split(raw).map_err(|_| refuse("malformed jwt"))?;
        if token.header.alg != "RS256" {
            return Err(refuse("malformed jwt: unexpected signature algorithm"));
        }
        let keys = self.keys.candidates(&token.header.kid).await.map_err(|error| IdTokenError(error.to_string()))?;
        if !keys.iter().any(|key| crate::rs256::verify(key, &token.signing_input, &token.signature)) {
            return Err(refuse("failed to verify signature"));
        }
        let registered: Registered = decode_object(&token.payload).map_err(|_| refuse("failed to unmarshal claims"))?;
        let claims: Value = serde_json::from_slice(&token.payload).map_err(|_| refuse("failed to unmarshal claims"))?;
        self.check(&registered)?;
        Ok(IdToken { subject: registered.sub.unwrap_or_default(), nonce: registered.nonce.unwrap_or_default(), claims })
    }

    fn check(&self, token: &Registered) -> Result<(), IdTokenError> {
        let refuse = |reason: &str| Err(IdTokenError(reason.to_owned()));
        let audience = audience(token.aud.clone()).map_err(|_| IdTokenError("failed to unmarshal claims".into()))?;
        let expiry = unix(token.exp.as_ref()).map_err(|_| IdTokenError("failed to unmarshal claims".into()))?;
        let not_before = token.nbf.as_ref().filter(|value| !value.is_null()).map(|value| unix(Some(value)));
        if token.iss.as_deref().unwrap_or_default() != self.issuer {
            return refuse("id token issued by a different provider");
        }
        if !audience.contains(&self.client_id) {
            return refuse("unexpected audience");
        }
        let now = (self.now)();
        if expiry < now {
            return refuse("token is expired");
        }
        match not_before {
            Some(Ok(nbf)) if now + NBF_LEEWAY < nbf => refuse("current time before the nbf time"),
            Some(Err(_)) => refuse("failed to unmarshal claims"),
            _ => Ok(()),
        }
    }
}

fn unix(value: Option<&Value>) -> Result<OffsetDateTime, ()> {
    let seconds = match value {
        None => 0,
        Some(Value::Number(number)) => number.as_i64().or_else(|| number.as_f64().map(|f| f as i64)).ok_or(())?,
        Some(_) => return Err(()),
    };
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| ())
}
