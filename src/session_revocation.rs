use time::OffsetDateTime;

use crate::store::StoreError;

/// The deletes that revoke more than the session at hand: back-channel logout, a "sign out
/// everywhere" button, and the expiry sweep.
#[async_trait::async_trait]
pub trait SessionRevocation: Send + Sync {
    /// Deletes every session of one account.
    async fn delete_by_user(&self, user_id: i64) -> Result<u64, StoreError>;
    /// Deletes the interactive logins of one account, keeping `except` and named tokens.
    async fn delete_logins(&self, user_id: i64, except: i64) -> Result<u64, StoreError>;
    /// Deletes one session of one account by id.
    async fn delete_by_id(&self, user_id: i64, session_id: i64) -> Result<(), StoreError>;
    /// Deletes sessions whose absolute lifetime ended before `now`.
    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError>;
}
