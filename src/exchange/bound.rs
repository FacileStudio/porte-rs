use tronc::bulle::{ForgetFuture, TokenFuture, TokenSource};

use super::{ExchangeError, Exchanger, Target};

/// An [`Exchanger`] bound to one user and one target: the `tronc::bulle::TokenSource` a Bulle
/// call made for that user takes. A 401 from Bulle forgets the cached token, so the client
/// retries once with a fresh one. Build it with [`Exchanger::bound`].
#[derive(Clone)]
pub struct Bound {
    exchanger: Exchanger,
    user_id: i64,
    target: Target,
}

impl Exchanger {
    /// The token source acting for `user_id` towards `target`, such as
    /// `Target::new("bulle", ["bulle.read", "bulle.write"])`. A zero `user_id` answers
    /// [`ExchangeError::NoUser`] and calls nobody.
    pub fn bound(&self, user_id: i64, target: Target) -> Bound {
        Bound { exchanger: self.clone(), user_id, target }
    }
}

impl TokenSource for Bound {
    fn token(&self) -> TokenFuture<'_> {
        Box::pin(async move {
            if self.user_id == 0 {
                return Err(ExchangeError::NoUser.into());
            }
            Ok(self.exchanger.token(self.user_id, &self.target).await?)
        })
    }

    fn forget(&self) -> Option<ForgetFuture<'_>> {
        self.exchanger.forget(self.user_id, &self.target);
        Some(Box::pin(std::future::ready(())))
    }
}
