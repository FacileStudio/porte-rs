use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use tronc::Error;

use super::Kit;
use super::exchange::decode_body;
use super::failure::no_store;
use crate::Session;
use crate::session::JwtVerifier;
use crate::wire::{DeviceExchangeRequest, ExchangeResponse};

impl Kit {
    pub(crate) async fn device(&self, request: Request) -> Response {
        no_store(match self.device_exchange(request).await {
            Ok(answer) => tronc::json::write(StatusCode::OK, &answer),
            Err(error) => error.into_response(),
        })
    }

    async fn device_exchange(&self, request: Request) -> Result<ExchangeResponse, Error> {
        let body: DeviceExchangeRequest = decode_body(request).await?;
        if body.access_token.is_empty() {
            return Err(Error::invalid("missing access_token"));
        }
        let verifier = self.inner.cli_tokens.as_ref().ok_or_else(|| Error::not_found("not found"))?;
        let identity = verifier.verify_jwt(&body.access_token).await.map_err(|error| {
            tracing::debug!(%error, "porte: device exchange refused");
            Error::unauthorized("invalid access token")
        })?;
        let template = Session {
            user_id: identity.user_id,
            provider: self.config().issuer.clone(),
            subject: identity.subject,
            ..Session::default()
        };
        let (token, _) = self.sessions().issue_for(None, template).await?;
        Ok(ExchangeResponse { user_id: identity.user_id.to_string(), token })
    }
}
