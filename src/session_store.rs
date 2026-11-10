use time::OffsetDateTime;

use crate::SessionRevocation;
use crate::store::{Session, StoreError};

/// The session rows. Every method takes a hash, never a token. The bulk deletes live in
/// [`SessionRevocation`], its supertrait, so an implementation is two `impl` blocks.
#[async_trait::async_trait]
pub trait SessionStore: SessionRevocation {
    /// Stores a session and returns it with its id. A binding (`provider` or `issued_by`) that
    /// no longer exists is [`StoreError::NotFound`].
    async fn create(&self, session: Session) -> Result<Session, StoreError>;
    /// One session, expired or not, or [`StoreError::NotFound`].
    async fn find(&self, token_hash: &str) -> Result<Session, StoreError>;
    /// Records a use, coalescing writes to one a minute.
    async fn touch(&self, token_hash: &str, at: OffsetDateTime) -> Result<(), StoreError>;
    /// Deletes one session by hash.
    async fn delete(&self, token_hash: &str) -> Result<(), StoreError>;
    /// Every session of one account, newest first.
    async fn list_by_user(&self, user_id: i64) -> Result<Vec<Session>, StoreError>;
}
