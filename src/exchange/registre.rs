use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use time::OffsetDateTime;

use super::reply::{Discovery, Failure, TokenReply, decode, reply_error, unavailable};
use super::user::Cached;
use super::{ExchangeError, Inner, Target};
use crate::TokenSet;
use crate::query::{encode_sorted, query_escape};

const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const FALLBACK_LIFE: time::Duration = time::Duration::minutes(1);

impl Inner {
    async fn token_endpoint(&self) -> Result<&str, ExchangeError> {
        let endpoint = self.endpoint.get_or_try_init(|| self.discover()).await?;
        Ok(endpoint.as_str())
    }

    async fn discover(&self) -> Result<String, ExchangeError> {
        let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer.trim_end_matches('/'));
        let response = self.cfg.http.get(&url).await.map_err(|error| unavailable(format!("discovery: {error}")))?;
        let status = response.status().as_u16();
        let document = decode::<Discovery>(response.body()).filter(|document| !document.token_endpoint.is_empty());
        match document {
            Some(document) if status == 200 => Ok(document.token_endpoint),
            _ => Err(unavailable(format!("discovery answered {status} with no token endpoint"))),
        }
    }

    async fn post(&self, form: Vec<(String, String)>) -> Result<TokenReply, Failure> {
        let endpoint = self.token_endpoint().await?;
        let basic = format!("{}:{}", query_escape(&self.cfg.client_id), query_escape(&self.cfg.client_secret));
        let request = http::Request::post(endpoint)
            .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(http::header::ACCEPT, "application/json")
            .header(http::header::AUTHORIZATION, format!("Basic {}", STANDARD.encode(basic)))
            .body(encode_sorted(&form).into_bytes())
            .map_err(unavailable)?;
        let response = self.cfg.http.send(request).await.map_err(unavailable)?;
        let status = response.status().as_u16();
        let reply = decode::<TokenReply>(response.body());
        match reply_error(status, reply.as_ref()) {
            Some(failure) => Err(failure),
            None => Ok(reply.unwrap_or_default()),
        }
    }

    pub(super) fn now(&self) -> OffsetDateTime {
        (self.cfg.clock)()
    }

    fn expiry(&self, seconds: i64) -> OffsetDateTime {
        match seconds {
            ..=0 => self.now() + FALLBACK_LIFE,
            _ => self.now() + time::Duration::seconds(seconds),
        }
    }

    pub(super) async fn refresh_grant(&self, refresh_token: &str) -> Result<TokenSet, Failure> {
        let form = vec![("grant_type".into(), "refresh_token".into()), ("refresh_token".into(), refresh_token.into())];
        let reply = self.post(form).await?;
        let refresh_token = match reply.refresh_token.is_empty() {
            true => refresh_token.to_owned(),
            false => reply.refresh_token,
        };
        Ok(TokenSet { access_token: reply.access_token, refresh_token, expiry: Some(self.expiry(reply.expires_in)) })
    }

    pub(super) async fn exchange(&self, subject: &str, target: &Target) -> Result<Cached, Failure> {
        let reply = self
            .post(vec![
                ("grant_type".into(), EXCHANGE_GRANT.into()),
                ("subject_token".into(), subject.into()),
                ("subject_token_type".into(), ACCESS_TOKEN_TYPE.into()),
                ("audience".into(), target.audience.clone()),
                ("scope".into(), target.scopes.join(" ")),
            ])
            .await?;
        Ok(Cached { value: reply.access_token, expiry: Some(self.expiry(reply.expires_in)) })
    }
}
