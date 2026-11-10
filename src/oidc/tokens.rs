use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use super::Kit;
use crate::TokenSet;
use crate::query::{encode_sorted, query_escape};

const EXPIRY_DELTA: time::Duration = time::Duration::seconds(10);

#[derive(Default, Deserialize)]
#[serde(default)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: Option<serde_json::Value>,
    id_token: Option<String>,
}

/// What the token endpoint granted: the tokens and the raw ID token, when one came back.
pub(crate) struct Grant {
    pub(crate) tokens: TokenSet,
    pub(crate) id_token: Option<String>,
}

impl Kit {
    /// The authorization code grant with the PKCE verifier, client authenticated with HTTP
    /// Basic as Go `oauth2` does first.
    pub(crate) async fn exchange_code(&self, code: &str, verifier: &str) -> Result<Grant, String> {
        let redirect = self.config().redirect_url.clone();
        self.token_request(vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.into()),
            ("redirect_uri".into(), redirect),
            ("code_verifier".into(), verifier.into()),
        ])
        .await
    }

    /// The refresh grant. A response without a new refresh token keeps the old one.
    pub(crate) async fn refresh(&self, tokens: &TokenSet) -> Result<Grant, String> {
        if tokens.refresh_token.is_empty() {
            return Err("no refresh token".into());
        }
        let params =
            vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), tokens.refresh_token.clone())];
        let mut grant = self.token_request(params).await?;
        if grant.tokens.refresh_token.is_empty() {
            grant.tokens.refresh_token = tokens.refresh_token.clone();
        }
        Ok(grant)
    }

    /// The tokens as they are, or refreshed when the access token expires within 10 s, as an
    /// `oauth2.TokenSource` would hand them out.
    pub(crate) async fn fresh(&self, tokens: &TokenSet) -> Result<TokenSet, String> {
        match tokens.expiry {
            Some(expiry) if expiry - EXPIRY_DELTA < self.now() => self.refresh(tokens).await.map(|grant| grant.tokens),
            _ => Ok(tokens.clone()),
        }
    }

    async fn token_request(&self, params: Vec<(String, String)>) -> Result<Grant, String> {
        let provider = self.provider().ok_or("OIDC is not configured")?;
        let cfg = self.config();
        let basic = STANDARD.encode(format!("{}:{}", query_escape(&cfg.client_id), query_escape(&cfg.client_secret)));
        let request = http::Request::post(&provider.token_endpoint)
            .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(http::header::AUTHORIZATION, format!("Basic {basic}"))
            .body(encode_sorted(&params).into_bytes())
            .map_err(|error| error.to_string())?;
        let response = self.inner.http.send(request).await.map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("token endpoint answered {}", response.status().as_u16()));
        }
        let body: TokenResponse = serde_json::from_slice(response.body()).map_err(|error| error.to_string())?;
        if body.access_token.is_empty() {
            return Err("server response missing access_token".into());
        }
        Ok(self.grant(body))
    }

    fn grant(&self, body: TokenResponse) -> Grant {
        let seconds = match body.expires_in {
            Some(serde_json::Value::Number(n)) => n.as_i64(),
            Some(serde_json::Value::String(s)) => s.parse().ok(),
            _ => None,
        };
        let expiry = seconds.filter(|s| *s > 0).map(|s| self.now() + time::Duration::seconds(s));
        let tokens = TokenSet { access_token: body.access_token, refresh_token: body.refresh_token, expiry };
        Grant { tokens, id_token: body.id_token.filter(|token| !token.is_empty()) }
    }
}
