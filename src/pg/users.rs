use sqlx::PgConnection;

use super::Store;
use super::linking::{by_verified_email, purge, refusal};
use crate::{Claims, StoreError, UserStore, normalize_locale};

#[derive(Default)]
pub(crate) struct Match {
    pub(crate) user_id: i64,
    pub(crate) by_email: bool,
    pub(crate) unverified: bool,
    pub(crate) inserted: bool,
}

#[async_trait::async_trait]
impl UserStore for Store {
    async fn upsert_from_oidc(&self, claims: &Claims) -> Result<i64, StoreError> {
        let mut claims = claims.clone();
        claims.email = claims.email.trim().to_lowercase();
        if claims.email.is_empty() {
            return Err(StoreError::other(format!(
                "porte/pg: the provider asserted no email for subject {:?}",
                claims.subject
            )));
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::other)?;
        let user_id = self.resolve_or_create(&mut tx, &claims).await?;
        sqlx::query(
            "INSERT INTO porte_identities (user_id, provider, subject) VALUES ($1, $2, $3)
             ON CONFLICT (provider, subject) DO UPDATE SET user_id = EXCLUDED.user_id",
        )
        .bind(user_id)
        .bind(&claims.provider)
        .bind(&claims.subject)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::other)?;
        tx.commit().await.map_err(StoreError::other)?;
        Ok(user_id)
    }
}

impl Store {
    async fn resolve_or_create(&self, tx: &mut PgConnection, claims: &Claims) -> Result<i64, StoreError> {
        let found = find_or_insert(tx, claims).await?;
        if found.inserted {
            return Ok(found.user_id);
        }
        if found.user_id == 0 {
            return Err(refusal(claims));
        }
        if found.by_email && found.unverified {
            purge(tx, &self.tables, found.user_id).await?;
        }
        update_user(tx, found.user_id, claims).await?;
        Ok(found.user_id)
    }
}

async fn find_or_insert(tx: &mut PgConnection, claims: &Claims) -> Result<Match, StoreError> {
    if let Some(found) = existing_user(tx, claims).await? {
        return Ok(found);
    }
    let inserted = insert_user(tx, claims).await?;
    if inserted != 0 {
        return Ok(Match { user_id: inserted, inserted: true, ..Match::default() });
    }
    Ok(existing_user(tx, claims).await?.unwrap_or_default())
}

async fn existing_user(tx: &mut PgConnection, claims: &Claims) -> Result<Option<Match>, StoreError> {
    let linked: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM porte_identities WHERE provider = $1 AND subject = $2")
            .bind(&claims.provider)
            .bind(&claims.subject)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::other)?;
    if let Some(user_id) = linked {
        return Ok(Some(Match { user_id, ..Match::default() }));
    }
    if !claims.email_verified {
        return Ok(None);
    }
    by_verified_email(tx, claims).await
}

async fn insert_user(tx: &mut PgConnection, claims: &Claims) -> Result<i64, StoreError> {
    let avatar_source = if claims.avatar_url.is_empty() { "" } else { "oidc" };
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO porte_users (email, email_verified, name, avatar_url, avatar_source, locale)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (email) DO NOTHING RETURNING id",
    )
    .bind(&claims.email)
    .bind(claims.email_verified)
    .bind(claims.display_name())
    .bind(&claims.avatar_url)
    .bind(avatar_source)
    .bind(normalize_locale(&claims.locale))
    .fetch_optional(&mut *tx)
    .await
    .map_err(StoreError::other)?;
    Ok(inserted.unwrap_or(0))
}

async fn update_user(tx: &mut PgConnection, user_id: i64, claims: &Claims) -> Result<(), StoreError> {
    let locale = if claims.locale.is_empty() { String::new() } else { normalize_locale(&claims.locale) };
    sqlx::query(
        "UPDATE porte_users
            SET email = CASE WHEN $3 THEN $2 ELSE email END,
                email_verified = email_verified OR $3,
                name = COALESCE(NULLIF($4, ''), name),
                avatar_url = COALESCE(NULLIF($5, ''), avatar_url),
                avatar_source = CASE WHEN $5 <> '' THEN 'oidc' ELSE avatar_source END,
                locale = COALESCE(NULLIF($6, ''), locale),
                updated_at = now()
          WHERE id = $1",
    )
    .bind(user_id)
    .bind(&claims.email)
    .bind(claims.email_verified)
    .bind(claims.display_name())
    .bind(&claims.avatar_url)
    .bind(locale)
    .execute(&mut *tx)
    .await
    .map(|_| ())
    .map_err(StoreError::other)
}
