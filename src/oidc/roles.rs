use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use time::OffsetDateTime;

use super::Kit;
use super::token_failure::TokenFailure;
use crate::{Identity, StoredIdentity, TokenSet};

const RETRY_INTERVAL: time::Duration = time::Duration::seconds(30);
const UNVERIFIED_GRACE: time::Duration = time::Duration::hours(1);

type Attempt = Arc<tokio::sync::Mutex<Option<OffsetDateTime>>>;

/// One lock per account around the role refresh, holding when it last failed. The provider
/// rotates the refresh token on every use, so two refreshes of one account must never overlap.
#[derive(Default)]
pub(super) struct Attempts(Mutex<HashMap<i64, Attempt>>);

impl Attempts {
    fn of(&self, user_id: i64) -> Attempt {
        let mut attempts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        attempts.retain(|_, attempt| {
            Arc::strong_count(attempt) > 1 || attempt.try_lock().is_ok_and(|failed_at| failed_at.is_some())
        });
        attempts.entry(user_id).or_default().clone()
    }
}

pub(super) fn show(identity: &mut Identity, stored: &StoredIdentity) {
    identity.roles = stored.roles.clone().unwrap_or_default();
    identity.roles_synced_at = stored.roles_synced_at;
}

impl Kit {
    pub(super) async fn stored_roles(&self, user_id: i64) -> Option<StoredIdentity> {
        self.identity_for(user_id)
            .await
            .inspect_err(|error| tracing::warn!(user_id, %error, "porte: failed to load claims"))
            .ok()
            .flatten()
    }

    /// Reads stale roles again from the provider and answers whether the sign-in still stands.
    ///
    /// A refused grant ends the account's logins and clears its stored roles and tokens. Any
    /// other failure keeps the cached roles without stamping them, for at most an hour past
    /// `claims_ttl`, and the next request after 30 s tries again.
    pub(super) async fn reverify(&self, identity: &mut Identity) -> bool {
        let attempt = self.inner.role_attempts.of(identity.user_id);
        let mut failed_at = attempt.lock().await;
        let Some(stored) = self.stored_roles(identity.user_id).await else { return true };
        let now = self.now();
        if !stored.roles_stale(now, self.config().claims_ttl) {
            show(identity, &stored);
            return true;
        }
        if failed_at.is_some_and(|at| now - at < RETRY_INTERVAL) {
            self.show_unverified(identity, &stored);
            return true;
        }
        match self.refresh_roles(stored.clone()).await {
            Ok(refreshed) => {
                *failed_at = None;
                show(identity, &refreshed);
                true
            }
            Err(TokenFailure::Refused(reason)) => {
                *failed_at = None;
                self.end_grant(stored, &reason).await;
                false
            }
            Err(TokenFailure::Other(reason)) => {
                tracing::warn!(user_id = identity.user_id, %reason, "porte: role refresh failed, roles stay unverified");
                *failed_at = Some(now);
                self.show_unverified(identity, &stored);
                true
            }
        }
    }

    fn show_unverified(&self, identity: &mut Identity, stored: &StoredIdentity) {
        let limit = self.config().claims_ttl + UNVERIFIED_GRACE;
        identity.roles_synced_at = stored.roles_synced_at;
        if stored.roles_synced_at.is_some_and(|at| self.now() - at < limit) {
            identity.roles = stored.roles.clone().unwrap_or_default();
        }
    }

    async fn end_grant(&self, mut stored: StoredIdentity, reason: &str) {
        let user_id = stored.user_id;
        tracing::warn!(user_id, %reason, "porte: the provider refused the refresh grant, ending the logins");
        (stored.roles, stored.roles_synced_at, stored.tokens) = (None, None, TokenSet::default());
        if let Err(error) = self.inner.identities.save(&stored).await {
            tracing::warn!(user_id, %error, "porte: failed to clear the refused roles and tokens");
        }
        if let Err(error) = self.sessions().revoke_logins(user_id, 0).await {
            tracing::warn!(user_id, %error, "porte: failed to end the logins of a refused grant");
        }
    }
}
