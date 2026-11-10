use std::collections::HashMap;
use std::sync::Mutex;

pub use super::codes::Codes;

use porte::{Claims, IdentityStore, StoreError, StoredIdentity, UserStore};
use time::OffsetDateTime;

#[derive(Default)]
pub struct Identities {
    pub rows: Mutex<HashMap<(String, String), StoredIdentity>>,
}

impl Identities {
    pub fn with(provider: &str, subject: &str, user_id: i64) -> Self {
        let identities = Identities::default();
        let row =
            StoredIdentity { user_id, provider: provider.into(), subject: subject.into(), ..StoredIdentity::default() };
        identities.rows.lock().unwrap().insert((provider.into(), subject.into()), row);
        identities
    }
}

#[async_trait::async_trait]
impl IdentityStore for Identities {
    async fn find(&self, provider: &str, subject: &str) -> Result<StoredIdentity, StoreError> {
        let rows = self.rows.lock().unwrap();
        rows.get(&(provider.to_owned(), subject.to_owned())).cloned().ok_or(StoreError::NotFound)
    }

    async fn save(&self, identity: &StoredIdentity) -> Result<(), StoreError> {
        let key = (identity.provider.clone(), identity.subject.clone());
        self.rows.lock().unwrap().insert(key, identity.clone());
        Ok(())
    }

    async fn mark_roles_synced(&self, provider: &str, subject: &str, at: OffsetDateTime) -> Result<(), StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.get_mut(&(provider.to_owned(), subject.to_owned())).ok_or(StoreError::NotFound)?;
        row.roles_synced_at = Some(at);
        Ok(())
    }

    async fn list_by_user(&self, user_id: i64) -> Result<Vec<StoredIdentity>, StoreError> {
        Ok(self.rows.lock().unwrap().values().filter(|row| row.user_id == user_id).cloned().collect())
    }
}

#[derive(Default)]
pub struct Users {
    pub claims: Mutex<Vec<Claims>>,
}

#[async_trait::async_trait]
impl UserStore for Users {
    async fn upsert_from_oidc(&self, claims: &Claims) -> Result<i64, StoreError> {
        self.claims.lock().unwrap().push(claims.clone());
        Ok(7)
    }
}
