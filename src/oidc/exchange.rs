use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::header::CONTENT_TYPE;
use tronc::Error;

use super::Kit;
use super::failure::{fail, no_store, redirect};
use super::flow::{pkce_challenge, valid_verifier};
use super::handoff::{Page, render};
use crate::query::encode_sorted;
use crate::wire::{ExchangeRequest, ExchangeResponse};
use crate::{LoginCode, Session, StoreError, hash_token, new_token};

const COMPLETE_FAILED: &str = "could not complete the login";
const INVALID_CODE: &str = "invalid or expired code";

impl Kit {
    pub(crate) async fn login_code(&self, bound: Session, port: &str, cli_state: &str) -> Response {
        let Ok(code) = new_token() else { return fail(self.config(), COMPLETE_FAILED) };
        let row = LoginCode {
            code_hash: hash_token(&code),
            user_id: bound.user_id,
            expires_at: self.now() + self.config().login_code_ttl,
            provider: bound.provider,
            subject: bound.subject,
        };
        if let Err(error) = self.inner.codes.create(&row).await {
            tracing::error!(%error, "porte: failed to store the login code");
            return fail(self.config(), COMPLETE_FAILED);
        }
        if !port.is_empty() {
            let mut query = vec![("code".to_owned(), code)];
            if !cli_state.is_empty() {
                query.push(("state".to_owned(), cli_state.to_owned()));
            }
            return redirect(&format!("http://127.0.0.1:{port}/?{}", encode_sorted(&query)));
        }
        no_store(self.code_page(&code))
    }

    fn code_page(&self, code: &str) -> Response {
        let cfg = self.config();
        let (app_name, logo_url) = (cfg.app_label(), cfg.logo());
        let hint = format!("The code is valid for {} seconds and works once.", cfg.login_code_ttl.as_secs());
        let page = render(&Page { app_name: &app_name, logo_url: &logo_url, hint: &hint, code });
        ([(CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response()
    }

    pub(crate) async fn exchange(&self, request: Request) -> Response {
        no_store(match self.redeem(request).await {
            Ok(answer) => tronc::json::write(StatusCode::OK, &answer),
            Err(error) => error.into_response(),
        })
    }

    async fn redeem(&self, request: Request) -> Result<ExchangeResponse, Error> {
        let body: ExchangeRequest = decode_body(request).await?;
        if body.code.is_empty() {
            return Err(Error::invalid("missing code"));
        }
        let mut lookup = body.code.clone();
        if !body.verifier.is_empty() {
            if !valid_verifier(&body.verifier) {
                return Err(Error::unauthorized(INVALID_CODE));
            }
            lookup = format!("{lookup}:{}", pkce_challenge(&body.verifier));
        }
        let code = match self.inner.codes.consume(&hash_token(&lookup)).await {
            Ok(code) => code,
            Err(StoreError::CodeConsumed) => {
                tracing::warn!("porte: login code replayed");
                return Err(Error::unauthorized(INVALID_CODE));
            }
            Err(StoreError::NotFound) => return Err(Error::unauthorized(INVALID_CODE)),
            Err(error) => return Err(Error::internal("failed to read the login code", error)),
        };
        if code.expired(self.now()) {
            return Err(Error::unauthorized(INVALID_CODE));
        }
        let template =
            Session { user_id: code.user_id, provider: code.provider, subject: code.subject, ..Session::default() };
        let (token, _) = self.sessions().issue_for(None, template).await?;
        Ok(ExchangeResponse { user_id: code.user_id.to_string(), token })
    }
}

pub(crate) async fn decode_body<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, Error> {
    let tronc::json::Json(body) = tronc::json::Json::<T>::from_request(request, &()).await?;
    Ok(body)
}
