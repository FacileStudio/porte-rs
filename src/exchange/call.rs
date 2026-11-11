use std::future::Future;

use super::{ExchangeError, Exchanger, Target};
use crate::Identity;

impl Exchanger {
    /// Runs `request` with the user's token for `target` as its bearer credential. When the
    /// downstream app answers 401, the token is forgotten and `request` runs once more with a
    /// freshly minted one; a second 401 is returned as it is. `request` must therefore build a
    /// new request each time it runs.
    pub async fn call<F, Fut, B, E>(
        &self,
        user_id: i64,
        target: &Target,
        mut request: F,
    ) -> Result<http::Response<B>, E>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = Result<http::Response<B>, E>>,
        E: From<ExchangeError>,
    {
        let response = request(self.token(user_id, target).await?).await?;
        if response.status() != http::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        drop(response);
        self.forget(user_id, target);
        request(self.token(user_id, target).await?).await
    }
}

/// An [`Exchanger`] bound to one target, acting for the identity porte authenticated on the
/// request. Its [`Source::token`] fits a client that takes a token source, such as tronc's
/// Bulle client.
#[derive(Clone)]
pub struct Source {
    exchanger: Exchanger,
    target: Target,
}

impl Source {
    pub(super) fn new(exchanger: Exchanger, target: Target) -> Self {
        Source { exchanger, target }
    }

    /// The target this source mints for.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// [`Exchanger::token`] for `identity`, or [`ExchangeError::NoUser`] when it has no user.
    pub async fn token(&self, identity: &Identity) -> Result<String, ExchangeError> {
        let user_id = signed_in(identity)?;
        self.exchanger.token(user_id, &self.target).await
    }

    /// [`Exchanger::forget`] for `identity`.
    pub fn forget(&self, identity: &Identity) {
        self.exchanger.forget(identity.user_id, &self.target);
    }

    /// [`Exchanger::call`] for `identity`, or [`ExchangeError::NoUser`] when it has no user.
    pub async fn call<F, Fut, B, E>(&self, identity: &Identity, request: F) -> Result<http::Response<B>, E>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = Result<http::Response<B>, E>>,
        E: From<ExchangeError>,
    {
        let user_id = signed_in(identity)?;
        self.exchanger.call(user_id, &self.target, request).await
    }
}

fn signed_in(identity: &Identity) -> Result<i64, ExchangeError> {
    match identity.user_id {
        0 => Err(ExchangeError::NoUser),
        user_id => Ok(user_id),
    }
}
