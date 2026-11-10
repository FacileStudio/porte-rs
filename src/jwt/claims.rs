use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use super::{JwtError, LEEWAY};

/// What a verified token says, field for field Go `jwt.Claims`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// `sub`.
    pub subject: String,
    /// `email`.
    pub email: String,
    /// `name`.
    pub name: String,
    /// `roles`, `None` when absent.
    pub roles: Option<Vec<String>>,
    /// `scope`, split on whitespace.
    pub scopes: Vec<String>,
    /// `act.sub`: the service acting for the user. A nested `act` is ignored.
    pub actor: String,
    /// `aud`, as a list.
    pub audience: Vec<String>,
    /// `client_id`.
    pub client_id: String,
    /// `jti`.
    pub id: String,
    /// `exp`.
    pub expires_at: OffsetDateTime,
    /// The profile claims.
    pub profile: Profile,
}

/// The profile claims of an access token. A claim of an odd type is dropped, not the token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// `email_verified`, `None` when absent or unreadable. `"true"`/`"1"` strings count.
    pub email_verified: Option<bool>,
    /// `preferred_username`.
    pub preferred_username: String,
    /// `picture`.
    pub picture: String,
    /// `locale`, when it is a string.
    pub locale: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct Payload {
    pub(crate) iss: Text,
    aud: Option<Value>,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: Text,
    sub: Text,
    email: Text,
    name: Text,
    roles: Option<Vec<String>>,
    scope: Text,
    act: Option<Actor>,
    client_id: Text,
    email_verified: Option<Value>,
    preferred_username: Text,
    picture: Text,
    locale: Option<Value>,
    #[serde(skip)]
    pub(crate) audience: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Actor {
    sub: Text,
}

pub(crate) type Text = Option<String>;

pub(crate) fn parse(bytes: &[u8]) -> Result<Payload, JwtError> {
    let mut payload: Payload = super::segments::decode_object(bytes)?;
    payload.audience = audience(payload.aud.take())?;
    Ok(payload)
}

pub(crate) fn audience(value: Option<Value>) -> Result<Vec<String>, JwtError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Null) => Ok(vec![String::new()]),
        Some(Value::String(one)) => Ok(vec![one]),
        Some(many) => serde_json::from_value(many).map_err(|_| JwtError::Malformed),
    }
}

impl Payload {
    pub(crate) fn issuer(&self) -> &str {
        self.iss.as_deref().unwrap_or_default()
    }

    pub(crate) fn within_validity(&self, now: OffsetDateTime) -> Result<(), JwtError> {
        let at = |unix: i64| OffsetDateTime::from_unix_timestamp(unix).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        if now > at(self.exp.unwrap_or(0)) + LEEWAY {
            return Err(JwtError::Expired);
        }
        if self.nbf.is_some_and(|nbf| nbf != 0 && now + LEEWAY < at(nbf)) {
            return Err(JwtError::NotYetValid);
        }
        if self.iat.is_some_and(|iat| iat != 0 && now + LEEWAY < at(iat)) {
            return Err(JwtError::IssuedInFuture);
        }
        Ok(())
    }

    pub(crate) fn into_claims(self) -> Claims {
        let text = |value: Text| value.unwrap_or_default();
        Claims {
            subject: text(self.sub),
            email: text(self.email),
            name: text(self.name),
            roles: self.roles,
            scopes: text(self.scope).split_whitespace().map(str::to_owned).collect(),
            actor: self.act.and_then(|act| act.sub).unwrap_or_default(),
            audience: self.audience,
            client_id: text(self.client_id),
            id: text(self.jti),
            expires_at: OffsetDateTime::from_unix_timestamp(self.exp.unwrap_or(0))
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            profile: Profile {
                email_verified: verified_claim(self.email_verified.as_ref()),
                preferred_username: text(self.preferred_username),
                picture: text(self.picture),
                locale: self.locale.and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default(),
            },
        }
    }
}

/// Reads `email_verified` as Go does: a bool, or one of `true True TRUE 1` / `false False FALSE 0`.
pub(crate) fn verified_claim(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(verified) => Some(*verified),
        Value::String(text) => match text.as_str() {
            "true" | "True" | "TRUE" | "1" => Some(true),
            "false" | "False" | "FALSE" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}
