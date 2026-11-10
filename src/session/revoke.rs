use super::Manager;
use crate::{Session, StoreError};

impl Manager {
    /// Every session of one account, newest first.
    pub async fn list(&self, user_id: i64) -> Result<Vec<Session>, StoreError> {
        self.store().list_by_user(user_id).await
    }

    /// Revokes one session of one account.
    pub async fn revoke(&self, user_id: i64, session_id: i64) -> Result<(), StoreError> {
        self.store().delete_by_id(user_id, session_id).await
    }

    /// Drops every session an account holds. Back-channel logout calls it.
    pub async fn revoke_user(&self, user_id: i64) -> Result<u64, StoreError> {
        self.store().delete_by_user(user_id).await
    }

    /// Drops the interactive logins of an account except `except`, keeping named tokens.
    pub async fn revoke_logins(&self, user_id: i64, except: i64) -> Result<u64, StoreError> {
        self.store().delete_logins(user_id, except).await
    }

    /// Deletes expired sessions. Nothing schedules it for you.
    pub async fn sweep(&self) -> Result<u64, StoreError> {
        self.store().delete_expired(self.now()).await
    }
}
