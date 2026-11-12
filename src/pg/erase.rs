use sqlx::{AssertSqlSafe, PgConnection};

use super::Store;
use super::locks::begin_locked;
use crate::StoreError;

enum Erased {
    Done,
    Moved,
}

impl Store {
    /// Deletes one identity with its sessions and login codes, leaving `porte_users` alone. The
    /// directory's deletion loop calls it after the app erased its own data.
    pub async fn erase_identity(&self, provider: &str, subject: &str) -> Result<(), StoreError> {
        for _ in 0..3 {
            let Some(user_id) =
                owner(&mut *self.pool.acquire().await.map_err(StoreError::other)?, provider, subject).await?
            else {
                return Ok(());
            };
            let mut tx = begin_locked(&self.pool, user_id, false).await?;
            if let Erased::Done = self.erase_locked(&mut tx, user_id, provider, subject).await? {
                return tx.commit().await.map_err(StoreError::other);
            }
        }
        Err(StoreError::other(format!("porte/pg: identity {subject} moved between accounts while erasing")))
    }

    /// Whether an account holds the `(provider, subject)` identity, matching the provider exactly
    /// as [`Store::erase_identity`] does. Pass the store to `directory::Deletions::with_holds`,
    /// so a person whose account came back after the erasure is erased again.
    pub async fn holds_identity(&self, provider: &str, subject: &str) -> Result<bool, StoreError> {
        let mut conn = self.pool.acquire().await.map_err(StoreError::other)?;
        owner(&mut conn, provider, subject).await.map(|owner| owner.is_some())
    }

    async fn erase_locked(
        &self,
        tx: &mut PgConnection,
        user_id: i64,
        provider: &str,
        subject: &str,
    ) -> Result<Erased, StoreError> {
        match owner(tx, provider, subject).await? {
            None => return Ok(Erased::Done),
            Some(current) if current != user_id => return Ok(Erased::Moved),
            Some(_) => {}
        }
        for table in self.tables.user_tables(tx, &["porte_sessions"]).await? {
            let query = format!("DELETE FROM {table} WHERE user_id = $1");
            sqlx::query(AssertSqlSafe(query)).bind(user_id).execute(&mut *tx).await.map_err(StoreError::other)?;
        }
        sqlx::query("DELETE FROM porte_identities WHERE provider = $1 AND subject = $2")
            .bind(provider)
            .bind(subject)
            .execute(&mut *tx)
            .await
            .map(|_| Erased::Done)
            .map_err(StoreError::other)
    }
}

async fn owner(conn: &mut PgConnection, provider: &str, subject: &str) -> Result<Option<i64>, StoreError> {
    sqlx::query_scalar("SELECT user_id FROM porte_identities WHERE provider = $1 AND subject = $2")
        .bind(provider)
        .bind(subject)
        .fetch_optional(conn)
        .await
        .map_err(StoreError::other)
}

#[cfg(feature = "directory")]
#[async_trait::async_trait]
impl crate::directory::IdentityEraser for Store {
    async fn erase_identity(&self, provider: &str, subject: &str) -> Result<(), crate::directory::DirectoryError> {
        Store::erase_identity(self, provider, subject)
            .await
            .map_err(|error| crate::directory::DirectoryError::Failed(error.to_string()))
    }
}

#[cfg(feature = "directory")]
#[async_trait::async_trait]
impl crate::directory::IdentityHolder for Store {
    async fn holds_identity(&self, provider: &str, subject: &str) -> Result<bool, crate::directory::DirectoryError> {
        Store::holds_identity(self, provider, subject)
            .await
            .map_err(|error| crate::directory::DirectoryError::Failed(error.to_string()))
    }
}
