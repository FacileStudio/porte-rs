use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use porte::jwt::{Claims, Profile};
use porte::{ErasedSubjects, StoreError};

use super::flow::{Flow, harness};
use super::provider::ISSUER;

#[derive(Default)]
pub struct Ledger {
    pub erased: Mutex<HashSet<String>>,
    pub fail: Mutex<bool>,
}

impl Ledger {
    pub fn erase(&self, subject: &str) {
        self.erased.lock().unwrap().insert(format!("{ISSUER}|{subject}"));
    }
}

#[async_trait::async_trait]
impl ErasedSubjects for Ledger {
    async fn erased(&self, provider: &str, subject: &str) -> Result<bool, StoreError> {
        if *self.fail.lock().unwrap() {
            return Err(StoreError::other("db is down"));
        }
        Ok(self.erased.lock().unwrap().contains(&format!("{provider}|{subject}")))
    }
}

pub async fn guarded() -> (Flow, Arc<Ledger>) {
    let flow = harness(|_, _| {}).await.unwrap();
    let ledger = Arc::new(Ledger::default());
    let _ = flow.kit.clone().with_erased(ledger.clone());
    (flow, ledger)
}

pub fn token(subject: &str) -> Claims {
    Claims {
        subject: subject.into(),
        email: "user@example.test".into(),
        name: "Test User".into(),
        roles: None,
        scopes: vec!["app.read".into()],
        actor: String::new(),
        audience: vec!["app-client".into()],
        client_id: "claude".into(),
        id: String::new(),
        expires_at: time::OffsetDateTime::now_utc(),
        profile: Profile { email_verified: Some(true), ..Profile::default() },
    }
}

pub fn upserts(flow: &Flow) -> usize {
    flow.users.claims.lock().unwrap().len()
}
