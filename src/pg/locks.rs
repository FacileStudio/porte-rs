use sqlx::{PgConnection, PgPool, Postgres, Transaction};

use crate::{Session, StoreError};

pub(crate) async fn lock_user(conn: &mut PgConnection, user_id: i64, shared: bool) -> Result<(), sqlx::Error> {
    let query = if shared {
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1 || $2::bigint::text, 0))"
    } else {
        "SELECT pg_advisory_xact_lock(hashtextextended($1 || $2::bigint::text, 0))"
    };
    sqlx::query(query).bind("porte/user:").bind(user_id).execute(conn).await.map(|_| ())
}

pub(crate) async fn begin_locked(
    pool: &PgPool,
    user_id: i64,
    shared: bool,
) -> Result<Transaction<'static, Postgres>, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::other)?;
    lock_user(&mut tx, user_id, shared).await.map_err(StoreError::other)?;
    Ok(tx)
}

pub(crate) fn bound(binding: &Session) -> bool {
    !binding.provider.is_empty() || binding.issued_by != 0
}

pub(crate) async fn vouched(conn: &mut PgConnection, binding: &Session) -> Result<(), StoreError> {
    let exists: bool = if binding.provider.is_empty() {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM porte_sessions WHERE id = $1 AND user_id = $2)")
            .bind(binding.issued_by)
            .bind(binding.user_id)
            .fetch_one(conn)
            .await
    } else {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM porte_identities WHERE provider = $1 AND subject = $2 AND user_id = $3)",
        )
        .bind(&binding.provider)
        .bind(&binding.subject)
        .bind(binding.user_id)
        .fetch_one(conn)
        .await
    }
    .map_err(StoreError::other)?;
    if exists { Ok(()) } else { Err(StoreError::NotFound) }
}
