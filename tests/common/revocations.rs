use porte::{SessionRevocation, StoreError};
use time::OffsetDateTime;

use super::memory::Sessions;

#[async_trait::async_trait]
impl SessionRevocation for Sessions {
    async fn delete_by_user(&self, user_id: i64) -> Result<u64, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| row.user_id != user_id);
        Ok((before - rows.len()) as u64)
    }

    async fn delete_logins(&self, user_id: i64, except: i64) -> Result<u64, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| row.user_id != user_id || !row.label.is_empty() || row.id == except);
        Ok((before - rows.len()) as u64)
    }

    async fn delete_by_id(&self, user_id: i64, session_id: i64) -> Result<(), StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| row.user_id != user_id || row.id != session_id);
        if rows.len() == before { Err(StoreError::NotFound) } else { Ok(()) }
    }

    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| !row.expired(now));
        Ok((before - rows.len()) as u64)
    }
}
