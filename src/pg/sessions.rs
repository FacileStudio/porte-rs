use sqlx::AssertSqlSafe;
use time::OffsetDateTime;

use super::Store;
use super::locks::{begin_locked, bound, vouched};
use super::rows::{SESSION_COLUMNS, require_one, session};
use crate::{Session, SessionStore, StoreError};

const INSERT: &str = "INSERT INTO porte_sessions (token_hash, user_id, label, created_at, last_used_at, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id";

#[async_trait::async_trait]
impl SessionStore for Store {
    async fn create(&self, mut new: Session) -> Result<Session, StoreError> {
        let now = OffsetDateTime::now_utc();
        let insert = sqlx::query_scalar::<_, i64>(INSERT)
            .bind(&new.token_hash)
            .bind(new.user_id)
            .bind(&new.label)
            .bind(new.created_at.unwrap_or(now))
            .bind(new.last_used_at.unwrap_or(now))
            .bind(new.expires_at);
        new.id = if bound(&new) {
            let mut tx = begin_locked(&self.pool, new.user_id, true).await?;
            vouched(&mut tx, &new).await?;
            let id = insert.fetch_one(&mut *tx).await.map_err(StoreError::other)?;
            tx.commit().await.map_err(StoreError::other)?;
            id
        } else {
            insert.fetch_one(&self.pool).await.map_err(StoreError::other)?
        };
        Ok(new)
    }

    async fn find(&self, token_hash: &str) -> Result<Session, StoreError> {
        let query = format!("SELECT {SESSION_COLUMNS} FROM porte_sessions WHERE token_hash = $1");
        let row = sqlx::query(AssertSqlSafe(query)).bind(token_hash).fetch_optional(&self.pool).await;
        let row = row.map_err(StoreError::other)?.ok_or(StoreError::NotFound)?;
        session(&row).map_err(StoreError::other)
    }

    async fn touch(&self, token_hash: &str, at: OffsetDateTime) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE porte_sessions SET last_used_at = $2
              WHERE token_hash = $1 AND last_used_at < $2::timestamptz - interval '1 minute'",
        )
        .bind(token_hash)
        .bind(at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(StoreError::other)
    }

    async fn delete(&self, token_hash: &str) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM porte_sessions WHERE token_hash = $1").bind(token_hash).execute(&self.pool);
        require_one(result.await)
    }

    async fn list_by_user(&self, user_id: i64) -> Result<Vec<Session>, StoreError> {
        let query = format!("SELECT {SESSION_COLUMNS} FROM porte_sessions WHERE user_id = $1 ORDER BY created_at DESC");
        let rows = sqlx::query(AssertSqlSafe(query)).bind(user_id).fetch_all(&self.pool).await;
        rows.map_err(StoreError::other)?.iter().map(|row| session(row).map_err(StoreError::other)).collect()
    }
}
