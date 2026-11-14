use std::time::Duration;

use http::HeaderValue;
use time::OffsetDateTime;
use tronc::Error;

use super::Manager;
use super::request::RequestView;
use super::rules::{has_csrf_header, ignore_missing, jwt_shaped, mutating};
use crate::{BROWSER_TOKEN_PREFIX, CSRF_HEADER_NAME, Identity, SESSION_COOKIE_NAME, Session, StoreError, hash_token};

const TOUCH_INTERVAL: Duration = Duration::from_secs(60);

/// The answer of [`Manager::authenticate`]: the identity or the refusal, plus the `Set-Cookie`
/// values to send either way (a dead cookie is cleared).
pub struct Authentication {
    /// The identity, or the suite error to answer with.
    pub result: Result<Identity, Error>,
    /// `Set-Cookie` values the response must carry.
    pub set_cookies: Vec<HeaderValue>,
}

impl Manager {
    /// Authenticates a request: the session cookie first, then `Authorization: Bearer`.
    ///
    /// It is what both middlewares run, exported for a caller outside a chain such as a
    /// WebSocket upgrade. A dead session row is deleted and its cookie cleared.
    pub async fn authenticate(&self, req: &(impl RequestView + Sync + ?Sized)) -> Authentication {
        let mut set_cookies = Vec::new();
        let result = self.resolve(req, &mut set_cookies).await;
        Authentication { result, set_cookies }
    }

    async fn resolve(
        &self,
        req: &(impl RequestView + Sync + ?Sized),
        cookies: &mut Vec<HeaderValue>,
    ) -> Result<Identity, Error> {
        let (token, from_cookie) = self.credential(req).ok_or_else(|| Error::unauthorized("missing auth"))?;
        if from_cookie && mutating(req.view().method) && !has_csrf_header(req) {
            return Err(Error::forbidden(format!("missing {CSRF_HEADER_NAME} header")));
        }
        if let Some(verifier) = self.jwt().filter(|_| !from_cookie && jwt_shaped(&token)) {
            let identity = verifier.verify_jwt(&token).await.map_err(|_| Error::unauthorized("invalid token"))?;
            return self.gate_scope(req, Identity { browser_session: false, ..identity });
        }
        let clear = |cookies: &mut Vec<HeaderValue>| {
            if from_cookie {
                cookies.extend(self.clear_cookie(req, SESSION_COOKIE_NAME));
            }
        };
        let hash = hash_token(&token);
        let stored = match self.store().find(&hash).await {
            Ok(stored) => stored,
            Err(StoreError::NotFound) => {
                clear(cookies);
                return Err(Error::unauthorized("invalid session"));
            }
            Err(error) => return Err(Error::internal("failed to read the session", error)),
        };
        let now = self.now();
        if stored.expired(now) || self.idled_out(&stored, from_cookie, now) {
            clear(cookies);
            self.drop_dead(&hash).await;
            return Err(Error::unauthorized("session expired"));
        }
        let browser_session = browser_session(from_cookie, &token, &stored);
        Ok(self.live(&stored, &hash, now, browser_session).await)
    }

    async fn live(&self, stored: &Session, hash: &str, now: OffsetDateTime, browser_session: bool) -> Identity {
        let due = stored.last_used_at.is_none_or(|last| now - last >= TOUCH_INTERVAL);
        if due && let Err(error) = self.store().touch(hash, now).await {
            tracing::warn!(%error, "porte: failed to record session use");
        }
        let mut identity =
            Identity { user_id: stored.user_id, session_id: stored.id, browser_session, ..Identity::default() };
        if let Some(claims) = self.claims() {
            claims.attach(&mut identity).await;
        }
        identity
    }

    async fn drop_dead(&self, hash: &str) {
        if let Err(error) = self.store().delete(hash).await.or_else(ignore_missing) {
            tracing::warn!(%error, "porte: failed to drop a dead session");
        }
    }

    fn credential(&self, req: &(impl RequestView + ?Sized)) -> Option<(String, bool)> {
        if let Some(value) = self.read_cookie(req, SESSION_COOKIE_NAME) {
            return Some((value, true));
        }
        let header = req.view().headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
        let prefix = header.get(..7).filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))?;
        let token = header[prefix.len()..].trim();
        (header.len() > 7 && !token.is_empty()).then(|| (token.to_owned(), false))
    }

    fn idled_out(&self, session: &Session, from_cookie: bool, now: OffsetDateTime) -> bool {
        let idle = self.config().idle_timeout();
        match session.last_used_at {
            Some(last) if from_cookie && !idle.is_zero() => now - last >= idle,
            _ => false,
        }
    }

    fn gate_scope(&self, req: &(impl RequestView + ?Sized), identity: Identity) -> Result<Identity, Error> {
        let prefix = &self.config().scope_prefix;
        if prefix.is_empty() {
            return Ok(identity);
        }
        let (write, read) = (format!("{prefix}.write"), format!("{prefix}.read"));
        let allowed =
            identity.scopes.iter().any(|scope| *scope == write || (!mutating(req.view().method) && *scope == read));
        if allowed { Ok(identity) } else { Err(Error::forbidden("insufficient scope")) }
    }
}

fn browser_session(from_cookie: bool, token: &str, stored: &Session) -> bool {
    from_cookie && !stored.is_api_token() && token.starts_with(BROWSER_TOKEN_PREFIX)
}
