use std::sync::Arc;
use std::time::Duration;

use super::reply::Failure;
use super::user::{Cached, Held, User};
use super::{ExchangeError, Inner};
use crate::{StoredIdentity, TokenSet};

const REFRESH_BUDGET: Duration = Duration::from_secs(30);

impl Inner {
    fn current_subject(&self, user: &User) -> Option<String> {
        let state = user.state();
        self.usable(&state.subject).then(|| state.subject.value.clone())
    }

    /// A Registre access token for the user, and whether it was refreshed just now. The guard
    /// is handed back so the caller keeps the user's lock for the exchange that follows.
    pub(super) async fn subject(
        self: Arc<Self>,
        user: Arc<User>,
        held: Held,
        user_id: i64,
        force: bool,
    ) -> Result<(Held, String, bool), ExchangeError> {
        if let Some(current) = self.current_subject(&user).filter(|_| !force) {
            return Ok((held, current, false));
        }
        let identity = self.identity(user_id).await?;
        let stored = Cached { value: identity.tokens.access_token.clone(), expiry: identity.tokens.expiry };
        if !force && user.state().pending.is_empty() && self.usable(&stored) {
            let value = stored.value.clone();
            user.set_subject(stored);
            return Ok((held, value, false));
        }
        let inner = self.clone();
        let task = tokio::spawn(async move {
            let refreshed = tokio::time::timeout(REFRESH_BUDGET, inner.refresh(&user, identity)).await;
            (held, refreshed.unwrap_or_else(|_| Err(ExchangeError::Unavailable("the refresh timed out".into()))))
        });
        match task.await {
            Ok((held, refreshed)) => refreshed.map(|access| (held, access, true)),
            Err(error) => Err(ExchangeError::Unavailable(format!("the refresh task failed: {error}"))),
        }
    }

    /// Trades the refresh token for a new access token and persists the rotated refresh token.
    /// It runs on its own task: once Registre has rotated the token, the new one must reach the
    /// store or the user is signed out.
    async fn refresh(&self, user: &User, identity: StoredIdentity) -> Result<String, ExchangeError> {
        let pending = user.state().pending.clone();
        let used = if pending.is_empty() { identity.tokens.refresh_token.clone() } else { pending };
        if used.is_empty() {
            return Err(ExchangeError::Reconnect);
        }
        let (identity, set) = match self.refresh_grant(&used).await {
            Err(Failure::GrantRejected) => self.refresh_rotated(identity, &used).await,
            set => (identity, set),
        };
        match set {
            Err(Failure::GrantRejected) => {
                user.set_pending(String::new());
                Err(ExchangeError::Reconnect)
            }
            Err(Failure::Other(error)) => Err(error),
            Ok(set) => {
                let access = set.access_token.clone();
                self.persist(user, identity, set).await;
                Ok(access)
            }
        }
    }

    /// Retries once when the stored refresh token is no longer the one just refused: another
    /// replica, or porte's own role refresh, rotated it in the meantime.
    async fn refresh_rotated(
        &self,
        identity: StoredIdentity,
        used: &str,
    ) -> (StoredIdentity, Result<TokenSet, Failure>) {
        let latest = match self.identity(identity.user_id).await {
            Ok(latest) if !latest.tokens.refresh_token.is_empty() && latest.tokens.refresh_token != used => latest,
            _ => return (identity, Err(Failure::GrantRejected)),
        };
        let set = self.refresh_grant(&latest.tokens.refresh_token).await;
        (latest, set)
    }

    async fn persist(&self, user: &User, mut identity: StoredIdentity, set: TokenSet) {
        user.set_subject(Cached { value: set.access_token.clone(), expiry: set.expiry });
        let rotated = set.refresh_token.clone();
        identity.tokens = set;
        match self.cfg.identities.save(&identity).await {
            Ok(()) => user.set_pending(String::new()),
            Err(error) => {
                user.set_pending(rotated);
                tracing::warn!(user_id = identity.user_id, %error, "exchange: the rotated refresh token was not saved, keeping it in memory");
            }
        }
    }

    /// The user's Registre identity: the federated row filed under the configured issuer. A user
    /// can hold several, such as a subject left over from a recreated Registre account, so the
    /// one holding a refresh token wins, and among those the most recently synced.
    pub(super) async fn identity(&self, user_id: i64) -> Result<StoredIdentity, ExchangeError> {
        let stored = self.cfg.identities.list_by_user(user_id).await;
        let stored = stored.map_err(|error| ExchangeError::Identities(error.to_string()))?;
        let issuer = self.cfg.issuer.trim_end_matches('/');
        stored
            .into_iter()
            .filter(|identity| identity.provider.trim_end_matches('/') == issuer && identity.password_hash.is_empty())
            .reduce(|best, candidate| if better(&candidate, &best) { candidate } else { best })
            .ok_or(ExchangeError::Reconnect)
    }
}

fn better(candidate: &StoredIdentity, current: &StoredIdentity) -> bool {
    let (has, had) = (!candidate.tokens.refresh_token.is_empty(), !current.tokens.refresh_token.is_empty());
    if has != had {
        return has;
    }
    candidate.synced_at > current.synced_at
}
