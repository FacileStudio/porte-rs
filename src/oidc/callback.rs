use axum::extract::Request;
use axum::response::Response;
use http::request::Parts;
use tronc::Error;

use super::Kit;
use super::failure::{GENERIC, fail, from_store, reason, redirect};
use super::flow::{FLOW_COOKIE, Flow};
use super::login::query_pairs;
use crate::session::append_cookies;
use crate::{Claims, Session, StoredIdentity, TokenSet, secure_compare};

impl Kit {
    pub(crate) async fn callback(&self, request: Request) -> Response {
        let (request, _) = request.into_parts();
        let Some(encoded) = self.sessions().read_cookie(&request, FLOW_COOKIE) else {
            return fail(self.config(), "the login has expired, start again");
        };
        let cleared = self.sessions().clear_cookie(&request, FLOW_COOKIE);
        let mut response = self.finish(&request, &encoded).await;
        append_cookies(response.headers_mut(), cleared);
        response
    }

    async fn finish(&self, request: &Parts, encoded: &str) -> Response {
        let query = query_pairs(&request.uri);
        let param = |key: &str| query.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or_default();
        let flow = match Flow::decode(encoded) {
            Some(flow) if secure_compare(&flow.state, param("state")) => flow,
            _ => return fail(self.config(), "the login could not be verified, start again"),
        };
        let bound = match self.complete(param("code"), &flow).await {
            Ok((claims, tokens)) => self.persist(claims, tokens).await,
            Err(error) => Err(error),
        };
        let bound = match bound {
            Ok(bound) => bound,
            Err(error) => {
                tracing::warn!(%error, "porte: the login did not complete");
                return fail(self.config(), &reason(&error));
            }
        };
        if flow.cli {
            return self.login_code(bound, &flow.port, &flow.cli_state).await;
        }
        self.browser_session(request, bound).await
    }

    async fn browser_session(&self, request: &Parts, bound: Session) -> Response {
        match self.sessions().issue_cookie_for(request, bound).await {
            Ok((_, _, cookie)) => {
                let mut response = redirect(&self.config().success_url);
                append_cookies(response.headers_mut(), [cookie]);
                response
            }
            Err(error) => {
                tracing::error!(%error, "porte: could not issue the session");
                fail(self.config(), GENERIC)
            }
        }
    }

    async fn complete(&self, code: &str, flow: &Flow) -> Result<(Claims, TokenSet), Error> {
        if code.is_empty() {
            return Err(Error::invalid("missing authorization code"));
        }
        let grant = self.exchange_code(code, &flow.verifier).await;
        let grant = grant.map_err(|cause| Error::internal("failed to exchange the authorization code", cause))?;
        let raw = grant.id_token.ok_or_else(|| Error::internal("the provider returned no id_token", "no id_token"))?;
        let provider = self.provider().ok_or_else(|| Error::internal(GENERIC, "OIDC is not configured"))?;
        let token = provider.id_tokens.verify(&raw).await.map_err(|_| Error::unauthorized("invalid id_token"))?;
        if !secure_compare(&token.nonce, &flow.nonce) {
            return Err(Error::unauthorized("id_token nonce mismatch"));
        }
        let claims = self.claims_from(&token.subject, &token.claims, true);
        let claims = claims.map_err(|message| Error::internal(message.clone(), message))?;
        if claims.email.is_empty() {
            return Err(Error::invalid("the identity provider returned no email"));
        }
        Ok((claims, grant.tokens))
    }

    /// Records the identity the way a login does: the app's user write, then the identity row
    /// with the tokens. Returns the session template bound to that identity.
    pub(crate) async fn persist(&self, mut claims: Claims, tokens: TokenSet) -> Result<Session, Error> {
        claims.tokens = tokens.clone();
        self.refuse_erased(&claims).await?;
        let user_id = self.inner.users.upsert_from_oidc(&claims).await.map_err(from_store)?;
        let now = self.now();
        let stored = StoredIdentity {
            user_id,
            provider: claims.provider.clone(),
            subject: claims.subject.clone(),
            tokens,
            roles: claims.roles.clone(),
            roles_synced_at: self.config().claims_enabled().then_some(now),
            synced_at: Some(now),
            ..StoredIdentity::default()
        };
        self.inner.identities.save(&stored).await.map_err(|e| Error::internal("failed to record the identity", e))?;
        Ok(Session { user_id, provider: claims.provider, subject: claims.subject, ..Session::default() })
    }
}
