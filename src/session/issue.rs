use http::HeaderValue;
use tronc::Error;

use super::Manager;
use super::request::RequestView;
use super::rules::ignore_missing;
use crate::{BROWSER_TOKEN_PREFIX, Identity, Session, StoreError, hash_token, new_browser_token, new_token};

impl Manager {
    /// Mints a session, stores only its hash and returns the plaintext once. A non-empty
    /// `label` makes the row a named API token that never expires.
    pub async fn issue(&self, user_id: i64, label: &str) -> Result<(String, Session), Error> {
        self.issue_for(None, Session { user_id, label: label.to_owned(), ..Session::default() }).await
    }

    /// Mints a session from a template. A `provider` or `issued_by` binding makes the insert
    /// conditional on that identity or session still existing. A named token minted by a caller
    /// for their own account is bound to the caller's session or subject.
    ///
    /// It mints a plain token, redrawn if it ever starts with [`crate::BROWSER_TOKEN_PREFIX`]:
    /// the CLI code exchange, the device exchange and named API tokens use it, so their sessions
    /// are never [`Identity::browser_session`].
    pub async fn issue_for(&self, caller: Option<&Identity>, template: Session) -> Result<(String, Session), Error> {
        self.mint(caller, template, plain_token).await
    }

    /// Go `IssueCookieFor`: [`Self::issue_for`] for a browser login, plus the session cookie to
    /// set. The token starts with [`crate::BROWSER_TOKEN_PREFIX`], so the cookie authenticates as
    /// [`Identity::browser_session`]. Only a sign-in the person made in this browser calls it.
    pub async fn issue_cookie_for(
        &self,
        req: &(impl RequestView + Sync + ?Sized),
        template: Session,
    ) -> Result<(String, Session, HeaderValue), Error> {
        let (token, session) = self.mint(None, template, new_browser_token).await?;
        let cookie = self.session_cookie(req, &token);
        Ok((token, session, cookie))
    }

    async fn mint(
        &self,
        caller: Option<&Identity>,
        template: Session,
        new: fn() -> Result<String, getrandom::Error>,
    ) -> Result<(String, Session), Error> {
        let token = new().map_err(|error| Error::internal("failed to issue a session", error))?;
        let mut session = bind_to_caller(&self.config().issuer, caller, template);
        let now = self.now();
        session.token_hash = hash_token(&token);
        session.created_at = Some(now);
        session.last_used_at = Some(now);
        session.expires_at = session.label.is_empty().then(|| now + self.config().session_ttl);
        match self.store().create(session).await {
            Ok(stored) => Ok((token, stored)),
            Err(StoreError::NotFound) => Err(Error::unauthorized("could not sign you in")),
            Err(error) => Err(Error::internal("failed to store the session", error)),
        }
    }

    /// Ends the session `identity` authenticated with. Ending another user's session by
    /// guessing an id is impossible: the delete matches the user id too.
    pub async fn end(&self, identity: &Identity) -> Result<(), Error> {
        self.store()
            .delete_by_id(identity.user_id, identity.session_id)
            .await
            .or_else(ignore_missing)
            .map_err(|error| Error::internal("failed to end the session", error))
    }
}

fn plain_token() -> Result<String, getrandom::Error> {
    loop {
        let token = new_token()?;
        if !token.starts_with(BROWSER_TOKEN_PREFIX) {
            return Ok(token);
        }
    }
}

fn bind_to_caller(issuer: &str, caller: Option<&Identity>, mut template: Session) -> Session {
    let Some(caller) = caller else { return template };
    if template.label.is_empty()
        || !template.provider.is_empty()
        || template.issued_by != 0
        || caller.user_id != template.user_id
    {
        return template;
    }
    if caller.session_id != 0 {
        template.issued_by = caller.session_id;
    } else if !caller.subject.is_empty() {
        template.provider = issuer.to_owned();
        template.subject = caller.subject.clone();
    }
    template
}
