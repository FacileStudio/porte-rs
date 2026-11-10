use std::collections::HashMap;

use axum::body::to_bytes;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::Value;
use tronc::Error;

use super::Kit;
use super::failure::no_store;
use super::form::parse_form;
use crate::StoreError;
use crate::wire::LogoutResponse;

const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const MAX_FORM_BYTES: usize = 10 << 20;

#[derive(Default, Deserialize)]
#[serde(default)]
struct LogoutClaims {
    events: Option<HashMap<String, Value>>,
    #[serde(rename = "jti")]
    _jti: Option<String>,
}

impl Kit {
    pub(crate) async fn backchannel(&self, request: Request) -> Response {
        no_store(match self.logout_subject(request).await {
            Ok(subject) => self.revoke_subject(&subject).await,
            Err(error) => error.into_response(),
        })
    }

    async fn logout_subject(&self, request: Request) -> Result<String, Error> {
        let raw = logout_token(request).await?;
        let provider = self.provider().ok_or_else(|| Error::not_found("not found"))?;
        let token = provider.id_tokens.verify(&raw).await.map_err(|_| Error::unauthorized("invalid logout token"))?;
        if !token.nonce.is_empty() {
            return Err(Error::unauthorized("a logout token must not carry a nonce"));
        }
        let bytes = serde_json::to_vec(&token.claims).unwrap_or_default();
        let claims: LogoutClaims =
            tronc::json::decode(&bytes, usize::MAX).map_err(|_| Error::unauthorized("unreadable logout token"))?;
        if !claims.events.unwrap_or_default().contains_key(LOGOUT_EVENT) {
            return Err(Error::unauthorized("logout token is missing the back-channel logout event"));
        }
        if token.subject.is_empty() {
            return Err(Error::unauthorized("logout token carries no subject"));
        }
        Ok(token.subject)
    }

    async fn revoke_subject(&self, subject: &str) -> Response {
        let stored = match self.inner.identities.find(&self.config().issuer, subject).await {
            Ok(stored) => stored,
            Err(StoreError::NotFound) => {
                return tronc::json::write(StatusCode::OK, &LogoutResponse { logged_out: true });
            }
            Err(error) => return Error::internal("failed to resolve the identity", error).into_response(),
        };
        match self.sessions().revoke_user(stored.user_id).await {
            Ok(deleted) => {
                tracing::info!(user_id = stored.user_id, sessions_revoked = deleted, "porte: back-channel logout");
                tronc::json::write(StatusCode::OK, &LogoutResponse { logged_out: true })
            }
            Err(error) => Error::internal("failed to revoke the sessions", error).into_response(),
        }
    }
}

async fn logout_token(request: Request) -> Result<String, Error> {
    let form = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"));
    let bytes =
        to_bytes(request.into_body(), MAX_FORM_BYTES).await.map_err(|_| Error::invalid("malformed logout request"))?;
    let pairs = match form {
        true => parse_form(&String::from_utf8_lossy(&bytes)).map_err(|_| Error::invalid("malformed logout request"))?,
        false => Vec::new(),
    };
    let token = pairs.into_iter().find(|(key, _)| key == "logout_token").map(|(_, value)| value).unwrap_or_default();
    if token.is_empty() {
        return Err(Error::invalid("missing logout_token"));
    }
    Ok(token)
}
