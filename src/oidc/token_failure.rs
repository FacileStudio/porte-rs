use serde::Deserialize;

use crate::http_client::HttpResponse;

#[derive(Default, Deserialize)]
#[serde(default)]
struct ErrorResponse {
    error: String,
}

/// Why a token request failed. `Refused` is the token endpoint answering `invalid_grant`: the
/// grant is gone for good. Anything else may pass, and is worth another try.
#[derive(Debug)]
pub(crate) enum TokenFailure {
    Refused(String),
    Other(String),
}

impl From<String> for TokenFailure {
    fn from(reason: String) -> Self {
        TokenFailure::Other(reason)
    }
}

impl From<&str> for TokenFailure {
    fn from(reason: &str) -> Self {
        TokenFailure::Other(reason.to_owned())
    }
}

impl From<TokenFailure> for String {
    fn from(failure: TokenFailure) -> Self {
        match failure {
            TokenFailure::Refused(reason) | TokenFailure::Other(reason) => reason,
        }
    }
}

pub(crate) fn refusal(response: &HttpResponse) -> TokenFailure {
    let reason = format!("token endpoint answered {}", response.status().as_u16());
    let reply: ErrorResponse = serde_json::from_slice(response.body()).unwrap_or_default();
    match response.status().is_client_error() && reply.error == "invalid_grant" {
        true => TokenFailure::Refused(reason),
        false => TokenFailure::Other(reason),
    }
}
