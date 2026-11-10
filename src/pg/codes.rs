use time::OffsetDateTime;

use super::Store;
use super::locks::{begin_locked, bound, vouched};
use crate::{LoginCode, LoginCodeStore, Session, StoreError};

#[async_trait::async_trait]
impl LoginCodeStore for Store {
    async fn create(&self, code: &LoginCode) -> Result<(), StoreError> {
        let insert = sqlx::query(
            "INSERT INTO porte_login_codes (code_hash, user_id, expires_at, provider, subject) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&code.code_hash)
        .bind(code.user_id)
        .bind(code.expires_at)
        .bind(&code.provider)
        .bind(&code.subject);
        let binding = Session {
            user_id: code.user_id,
            provider: code.provider.clone(),
            subject: code.subject.clone(),
            ..Session::default()
        };
        if !bound(&binding) {
            return insert.execute(&self.pool).await.map(|_| ()).map_err(StoreError::other);
        }
        let mut tx = begin_locked(&self.pool, code.user_id, true).await?;
        vouched(&mut tx, &binding).await?;
        insert.execute(&mut *tx).await.map_err(StoreError::other)?;
        tx.commit().await.map_err(StoreError::other)
    }

    async fn consume(&self, code_hash: &str) -> Result<LoginCode, StoreError> {
        let row: Option<(String, i64, OffsetDateTime, String, String)> = sqlx::query_as(
            "UPDATE porte_login_codes SET consumed_at = $2
              WHERE code_hash = $1 AND consumed_at IS NULL
          RETURNING code_hash, user_id, expires_at,
                    COALESCE(to_jsonb(porte_login_codes) ->> 'provider', ''),
                    COALESCE(to_jsonb(porte_login_codes) ->> 'subject', '')",
        )
        .bind(code_hash)
        .bind(OffsetDateTime::now_utc())
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::other)?;
        match row {
            Some((code_hash, user_id, expires_at, provider, subject)) => {
                Ok(LoginCode { code_hash, user_id, expires_at, provider, subject })
            }
            None => Err(self.why_it_failed(code_hash).await),
        }
    }

    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM porte_login_codes WHERE expires_at < $1").bind(now).execute(&self.pool);
        result.await.map(|done| done.rows_affected()).map_err(StoreError::other)
    }
}

impl Store {
    async fn why_it_failed(&self, code_hash: &str) -> StoreError {
        let consumed: Result<Option<Option<OffsetDateTime>>, _> =
            sqlx::query_scalar("SELECT consumed_at FROM porte_login_codes WHERE code_hash = $1")
                .bind(code_hash)
                .fetch_optional(&self.pool)
                .await;
        match consumed {
            Ok(Some(Some(_))) => StoreError::CodeConsumed,
            Ok(_) => StoreError::NotFound,
            Err(error) => StoreError::other(error),
        }
    }
}
