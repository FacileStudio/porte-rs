use std::sync::atomic::{AtomicUsize, Ordering};

use porte::{Claims, StoreError, UserStore};

pub struct ScriptedUsers {
    pub id: i64,
    pub mode: String,
    pub calls: AtomicUsize,
}

impl ScriptedUsers {
    pub fn new(id: i64, mode: &str) -> Self {
        ScriptedUsers { id, mode: mode.to_owned(), calls: AtomicUsize::new(0) }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl UserStore for ScriptedUsers {
    async fn upsert_from_oidc(&self, _: &Claims) -> Result<i64, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode.as_str() {
            "refuses" | "refused" => Err(StoreError::Refused(tronc::Error::forbidden("this account is disabled"))),
            "fails" => Err(StoreError::other("the database is down")),
            _ => Ok(self.id),
        }
    }
}
