use std::collections::HashMap;
use std::sync::Mutex;

use porte::{LoginCode, LoginCodeStore, StoreError};
use time::OffsetDateTime;

#[derive(Default)]
pub struct Codes {
    pub rows: Mutex<HashMap<String, (LoginCode, bool)>>,
}

#[async_trait::async_trait]
impl LoginCodeStore for Codes {
    async fn create(&self, code: &LoginCode) -> Result<(), StoreError> {
        self.rows.lock().unwrap().insert(code.code_hash.clone(), (code.clone(), false));
        Ok(())
    }

    async fn consume(&self, code_hash: &str) -> Result<LoginCode, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        match rows.get_mut(code_hash) {
            None => Err(StoreError::NotFound),
            Some((_, true)) => Err(StoreError::CodeConsumed),
            Some((code, consumed)) => {
                *consumed = true;
                Ok(code.clone())
            }
        }
    }

    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|_, (code, _)| !code.expired(now));
        Ok((before - rows.len()) as u64)
    }
}
