use time::OffsetDateTime;

use super::Store;
use super::rows::require_one;
use crate::{SessionRevocation, StoreError};

#[async_trait::async_trait]
impl SessionRevocation for Store {
    async fn delete_by_user(&self, user_id: i64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM porte_sessions WHERE user_id = $1").bind(user_id).execute(&self.pool);
        result.await.map(|done| done.rows_affected()).map_err(StoreError::other)
    }

    async fn delete_logins(&self, user_id: i64, except: i64) -> Result<u64, StoreError> {
        sqlx::query("DELETE FROM porte_sessions WHERE user_id = $1 AND label = '' AND ($2 = 0 OR id <> $2)")
            .bind(user_id)
            .bind(except)
            .execute(&self.pool)
            .await
            .map(|done| done.rows_affected())
            .map_err(StoreError::other)
    }

    async fn delete_by_id(&self, user_id: i64, session_id: i64) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM porte_sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(user_id)
            .execute(&self.pool);
        require_one(result.await)
    }

    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM porte_sessions WHERE expires_at IS NOT NULL AND expires_at < $1")
            .bind(now)
            .execute(&self.pool);
        result.await.map(|done| done.rows_affected()).map_err(StoreError::other)
    }
}
