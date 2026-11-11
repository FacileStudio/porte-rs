use serde::Deserialize;

use super::ExchangeError;

const MAX_BODY: usize = 1 << 20;

pub(super) enum Failure {
    GrantRejected,
    Other(ExchangeError),
}

impl From<ExchangeError> for Failure {
    fn from(error: ExchangeError) -> Self {
        Failure::Other(error)
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct TokenReply {
    pub(super) access_token: String,
    pub(super) refresh_token: String,
    pub(super) expires_in: i64,
    pub(super) error: String,
}

#[derive(Deserialize)]
pub(super) struct Discovery {
    #[serde(default)]
    pub(super) token_endpoint: String,
}

pub(super) fn unavailable(reason: impl std::fmt::Display) -> ExchangeError {
    ExchangeError::Unavailable(reason.to_string())
}

pub(super) fn reply_error(status: u16, reply: Option<&TokenReply>) -> Option<Failure> {
    let ok = status == 200;
    match reply {
        _ if status >= 500 => Some(unavailable(format!("the token endpoint answered {status}")).into()),
        None if ok => Some(unavailable("the token endpoint answered 200 with an unreadable body").into()),
        Some(reply) if ok && reply.access_token.is_empty() => {
            Some(unavailable("the token endpoint answered 200 with no access token").into())
        }
        _ if ok => None,
        Some(reply) if reply.error == "invalid_grant" => Some(Failure::GrantRejected),
        Some(reply) if !reply.error.is_empty() => {
            Some(ExchangeError::Refused { status, code: reply.error.clone() }.into())
        }
        _ => Some(ExchangeError::Refused { status, code: "unknown".into() }.into()),
    }
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Option<T> {
    if body.len() > MAX_BODY {
        return None;
    }
    serde_json::from_slice(body).ok()
}
