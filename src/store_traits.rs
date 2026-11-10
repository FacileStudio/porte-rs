use time::OffsetDateTime;

use crate::identity::{Claims, StoredIdentity};
use crate::store::{LoginCode, StoreError};

/// The app's user write: called once per successful callback.
#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    /// Matches on `(provider, subject)`, falls back to the email only when it is verified, and
    /// returns the account id.
    async fn upsert_from_oidc(&self, claims: &Claims) -> Result<i64, StoreError>;
}

/// The `porte_identities` rows.
#[async_trait::async_trait]
pub trait IdentityStore: Send + Sync {
    /// One identity, or [`StoreError::NotFound`].
    async fn find(&self, provider: &str, subject: &str) -> Result<StoredIdentity, StoreError>;
    /// Inserts or updates the whole row by `(provider, subject)`.
    async fn save(&self, identity: &StoredIdentity) -> Result<(), StoreError>;
    /// Moves only `roles_synced_at`.
    async fn mark_roles_synced(&self, provider: &str, subject: &str, at: OffsetDateTime) -> Result<(), StoreError>;
    /// Every identity of one account.
    async fn list_by_user(&self, user_id: i64) -> Result<Vec<StoredIdentity>, StoreError>;
}

/// The one-time CLI login codes.
#[async_trait::async_trait]
pub trait LoginCodeStore: Send + Sync {
    /// Stores a code.
    async fn create(&self, code: &LoginCode) -> Result<(), StoreError>;
    /// Claims a code atomically: [`StoreError::CodeConsumed`] on a replay,
    /// [`StoreError::NotFound`] when it never existed.
    async fn consume(&self, code_hash: &str) -> Result<LoginCode, StoreError>;
    /// Drops codes that expired before `now`.
    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError>;
}
