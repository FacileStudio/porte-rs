use std::sync::Arc;

use super::reply::Failure;
use super::user::{Cached, Held, User};
use super::{ExchangeError, Inner, Target};

impl Inner {
    fn remember(&self, user: &User, key: String, token: Cached) {
        if self.usable(&token) {
            user.state().tokens.insert(key, token);
        }
    }

    pub(super) async fn mint(
        self: Arc<Self>,
        user: Arc<User>,
        held: Held,
        user_id: i64,
        target: &Target,
    ) -> Result<String, ExchangeError> {
        let (held, subject, fresh) = self.clone().subject(user.clone(), held, user_id, false).await?;
        let (held, minted) = match self.exchange(&subject, target).await {
            Err(Failure::GrantRejected) if !fresh => {
                let (held, subject, _) = self.clone().subject(user.clone(), held, user_id, true).await?;
                (held, self.exchange(&subject, target).await)
            }
            minted => (held, minted),
        };
        let outcome = match minted {
            Err(Failure::GrantRejected) => {
                user.set_subject(Cached::default());
                Err(ExchangeError::Reconnect)
            }
            Err(Failure::Other(error)) => Err(error),
            Ok(token) => {
                let value = token.value.clone();
                self.remember(&user, target.key(), token);
                Ok(value)
            }
        };
        drop(held);
        outcome
    }
}
