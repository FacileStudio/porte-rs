use std::collections::HashMap;
use std::sync::Mutex;

use porte::{Session, SessionStore, StoreError};

use time::OffsetDateTime;

#[derive(Default)]
pub struct Sessions {
    pub(crate) rows: Mutex<Vec<Session>>,
}

impl Sessions {
    pub fn count(&self, user_id: i64) -> usize {
        self.rows.lock().unwrap().iter().filter(|row| row.user_id == user_id).count()
    }

    pub fn by_hash(&self) -> HashMap<String, Session> {
        self.rows.lock().unwrap().iter().map(|row| (row.token_hash.clone(), row.clone())).collect()
    }
}

#[async_trait::async_trait]
impl SessionStore for Sessions {
    async fn create(&self, mut session: Session) -> Result<Session, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        session.id = rows.len() as i64 + 1;
        rows.push(session.clone());
        Ok(session)
    }

    async fn find(&self, token_hash: &str) -> Result<Session, StoreError> {
        self.rows.lock().unwrap().iter().find(|row| row.token_hash == token_hash).cloned().ok_or(StoreError::NotFound)
    }

    async fn touch(&self, token_hash: &str, at: OffsetDateTime) -> Result<(), StoreError> {
        let mut rows = self.rows.lock().unwrap();
        rows.iter_mut().filter(|row| row.token_hash == token_hash).for_each(|row| row.last_used_at = Some(at));
        Ok(())
    }

    async fn delete(&self, token_hash: &str) -> Result<(), StoreError> {
        self.rows.lock().unwrap().retain(|row| row.token_hash != token_hash);
        Ok(())
    }

    async fn list_by_user(&self, user_id: i64) -> Result<Vec<Session>, StoreError> {
        Ok(self.rows.lock().unwrap().iter().filter(|row| row.user_id == user_id).cloned().collect())
    }
}
