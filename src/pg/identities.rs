use sqlx::AssertSqlSafe;
use time::OffsetDateTime;

use super::Store;
use super::locks::begin_locked;
use super::rows::{IDENTITY_COLUMNS, identity, require_one, roles_json};
use super::sealer::seal;
use crate::{IdentityStore, StoreError, StoredIdentity};

const SAVE: &str = "INSERT INTO porte_identities
       (user_id, provider, subject, password_hash, access_token, refresh_token,
        token_expiry, roles, roles_synced_at, synced_at)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
 WHERE EXISTS (SELECT 1 FROM porte_identities WHERE provider = $2 AND subject = $3 AND user_id = $1)
    OR NOT EXISTS (SELECT 1 FROM porte_identities WHERE provider = $2 AND user_id = $1)
ON CONFLICT (provider, subject) DO UPDATE SET
       password_hash = EXCLUDED.password_hash, access_token = EXCLUDED.access_token,
       refresh_token = EXCLUDED.refresh_token, token_expiry = EXCLUDED.token_expiry,
       roles = EXCLUDED.roles, roles_synced_at = EXCLUDED.roles_synced_at,
       synced_at = EXCLUDED.synced_at
 WHERE porte_identities.user_id = EXCLUDED.user_id";

#[async_trait::async_trait]
impl IdentityStore for Store {
    async fn find(&self, provider: &str, subject: &str) -> Result<StoredIdentity, StoreError> {
        let query = format!("SELECT {IDENTITY_COLUMNS} FROM porte_identities WHERE provider = $1 AND subject = $2");
        let row = sqlx::query(AssertSqlSafe(query)).bind(provider).bind(subject).fetch_optional(&self.pool).await;
        let row = row.map_err(StoreError::other)?.ok_or(StoreError::NotFound)?;
        identity(&row, self.sealer.as_deref()).map_err(StoreError::other)
    }

    async fn save(&self, stored: &StoredIdentity) -> Result<(), StoreError> {
        let access = seal(self.sealer.as_deref(), &stored.tokens.access_token).map_err(StoreError::other)?;
        let refresh = seal(self.sealer.as_deref(), &stored.tokens.refresh_token).map_err(StoreError::other)?;
        let mut tx = begin_locked(&self.pool, stored.user_id, false).await?;
        let written = sqlx::query(SAVE)
            .bind(stored.user_id)
            .bind(&stored.provider)
            .bind(&stored.subject)
            .bind(&stored.password_hash)
            .bind(access)
            .bind(refresh)
            .bind(stored.tokens.expiry)
            .bind(roles_json(stored.roles.as_ref()))
            .bind(stored.roles_synced_at)
            .bind(stored.synced_at)
            .execute(&mut *tx)
            .await;
        require_one(written)?;
        tx.commit().await.map_err(StoreError::other)
    }

    async fn mark_roles_synced(&self, provider: &str, subject: &str, at: OffsetDateTime) -> Result<(), StoreError> {
        let result =
            sqlx::query("UPDATE porte_identities SET roles_synced_at = $3 WHERE provider = $1 AND subject = $2")
                .bind(provider)
                .bind(subject)
                .bind(at)
                .execute(&self.pool);
        require_one(result.await)
    }

    async fn list_by_user(&self, user_id: i64) -> Result<Vec<StoredIdentity>, StoreError> {
        let query = format!("SELECT {IDENTITY_COLUMNS} FROM porte_identities WHERE user_id = $1 ORDER BY provider");
        let rows = sqlx::query(AssertSqlSafe(query)).bind(user_id).fetch_all(&self.pool).await;
        let rows = rows.map_err(StoreError::other)?;
        rows.iter().map(|row| identity(row, self.sealer.as_deref()).map_err(StoreError::other)).collect()
    }
}

impl Store {
    /// The `(provider, subject)` that `user_id` signs in with at `provider`, from
    /// `porte_identities`, or [`StoreError::NotFound`]. An account holds at most one identity per
    /// provider, so the answer is unique. Pass the issuer to get the Registre subject of a
    /// cookie session, where [`crate::Identity::subject`] is empty as in Go porte.
    pub async fn find_by_user(&self, provider: &str, user_id: i64) -> Result<(String, String), StoreError> {
        let row = sqlx::query_as("SELECT provider, subject FROM porte_identities WHERE provider = $1 AND user_id = $2")
            .bind(provider)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await;
        row.map_err(StoreError::other)?.ok_or(StoreError::NotFound)
    }
}
