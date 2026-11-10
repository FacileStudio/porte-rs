use sqlx::{AssertSqlSafe, PgConnection};

use super::locks::lock_user;
use super::tables::TableSet;
use super::users::Match;
use crate::{Claims, StoreError};

pub(crate) fn refusal(claims: &Claims) -> StoreError {
    let reason = if claims.email_verified {
        "already belongs to another identity of this provider, so porte will not link a second one"
    } else {
        "is already registered under a different identity, and the provider did not verify the address, so porte will not link them"
    };
    StoreError::other(format!("porte/pg: {} {reason}", claims.email))
}

pub(crate) async fn by_verified_email(tx: &mut PgConnection, claims: &Claims) -> Result<Option<Match>, StoreError> {
    let user_id: Option<i64> = sqlx::query_scalar("SELECT id FROM porte_users WHERE email = $1")
        .bind(&claims.email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::other)?;
    let Some(user_id) = user_id else { return Ok(None) };
    lock_user(tx, user_id, false).await.map_err(StoreError::other)?;
    let row: Option<(bool, bool)> = sqlx::query_as(
        "SELECT u.email_verified,
                EXISTS (SELECT 1 FROM porte_identities i WHERE i.user_id = u.id AND i.provider = $3)
           FROM porte_users u WHERE u.id = $1 AND u.email = $2",
    )
    .bind(user_id)
    .bind(&claims.email)
    .bind(&claims.provider)
    .fetch_optional(&mut *tx)
    .await
    .map_err(StoreError::other)?;
    let Some((verified, linked)) = row else { return Ok(None) };
    let found = Match { user_id, by_email: true, unverified: !verified, inserted: false };
    Ok((found.unverified || !linked).then_some(found))
}

pub(crate) async fn purge(tx: &mut PgConnection, tables: &TableSet, user_id: i64) -> Result<(), StoreError> {
    for table in tables.user_tables(tx, &["porte_identities", "porte_sessions"]).await? {
        let query = format!("DELETE FROM {table} WHERE user_id = $1");
        sqlx::query(AssertSqlSafe(query)).bind(user_id).execute(&mut *tx).await.map_err(StoreError::other)?;
    }
    Ok(())
}
