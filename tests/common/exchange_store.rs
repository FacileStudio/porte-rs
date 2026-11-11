use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use porte::{IdentityStore, StoreError, StoredIdentity};
use time::OffsetDateTime;

#[derive(Default)]
pub struct Identities {
    pub rows: Mutex<HashMap<i64, StoredIdentity>>,
    pub saves: AtomicI32,
    pub failing: AtomicBool,
    pub stale: Mutex<String>,
}

impl Identities {
    pub fn refresh_token(&self, user_id: i64) -> String {
        self.rows.lock().unwrap()[&user_id].tokens.refresh_token.clone()
    }

    pub fn set_refresh_token(&self, user_id: i64, token: String) {
        self.rows.lock().unwrap().get_mut(&user_id).unwrap().tokens.refresh_token = token;
    }
}

#[async_trait::async_trait]
impl IdentityStore for Identities {
    async fn find(&self, _: &str, _: &str) -> Result<StoredIdentity, StoreError> {
        Err(StoreError::NotFound)
    }

    async fn save(&self, identity: &StoredIdentity) -> Result<(), StoreError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(StoreError::other("database down"));
        }
        self.saves.fetch_add(1, Ordering::SeqCst);
        self.rows.lock().unwrap().insert(identity.user_id, identity.clone());
        Ok(())
    }

    async fn mark_roles_synced(&self, _: &str, _: &str, _: OffsetDateTime) -> Result<(), StoreError> {
        Ok(())
    }

    async fn list_by_user(&self, user_id: i64) -> Result<Vec<StoredIdentity>, StoreError> {
        let Some(mut row) = self.rows.lock().unwrap().get(&user_id).cloned() else {
            return Ok(Vec::new());
        };
        let stale = std::mem::take(&mut *self.stale.lock().unwrap());
        if !stale.is_empty() {
            row.tokens.refresh_token = stale;
        }
        let local = StoredIdentity {
            user_id,
            provider: "local".into(),
            subject: "1".into(),
            password_hash: "x".into(),
            ..StoredIdentity::default()
        };
        let leftover = StoredIdentity {
            user_id,
            provider: row.provider.clone(),
            subject: "old".into(),
            ..StoredIdentity::default()
        };
        Ok(vec![local, leftover, row])
    }
}
