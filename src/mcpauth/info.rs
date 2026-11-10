use axum::extract::FromRequestParts;
use http::request::Parts;
use time::OffsetDateTime;
use tronc::Error;

use crate::Identity;

/// The client id of a token Bulle exchanged for the user.
pub const BULLE_CLIENT_ID: &str = "bulle";

/// What a verified MCP token grants, inserted in the request extensions by [`super::Require`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    /// The local account id, as a decimal string.
    pub user_id: String,
    /// The granted scopes, with `<prefix>.read` added when `<prefix>.write` is held.
    pub scopes: Vec<String>,
    /// `exp`.
    pub expiration: OffsetDateTime,
    /// `client_id`: the MCP client the user authorised.
    pub client_id: String,
    /// `act.sub`, when a service acts for the user.
    pub actor: String,
    /// The issuer's subject.
    pub subject: String,
}

/// False only for a token Bulle exchanged (`act` present and `client_id` = `bulle`).
pub fn third_party(info: Option<&TokenInfo>) -> bool {
    info.is_none_or(|info| info.actor.is_empty() || info.client_id != BULLE_CLIENT_ID)
}

/// The porte identity a token stands for: user id, subject, scopes and actor.
pub fn identity(info: Option<&TokenInfo>) -> Option<Identity> {
    let info = info?;
    let user_id = info.user_id.parse::<i64>().ok().filter(|id| *id != 0)?;
    Some(Identity {
        user_id,
        subject: info.subject.clone(),
        scopes: info.scopes.clone(),
        actor: info.actor.clone(),
        ..Identity::default()
    })
}

impl<S: Send + Sync> FromRequestParts<S> for TokenInfo {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<TokenInfo>().cloned().ok_or_else(|| Error::unauthorized("not authenticated"))
    }
}
