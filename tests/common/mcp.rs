use std::sync::Arc;

use porte::mcpauth::{Config, Verifier};
use porte::{IdentityStore, StoreError, StoredIdentity};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::idp::{ISSUER, fixture_client};
use super::sign::{merge, now, sign};
use super::stores::Identities;

pub const RESOURCE: &str = "https://courrier.example/mcp";
pub const APP_AUDIENCE: &str = "app-client";
pub const SUBJECT: &str = "user-sub";

pub fn mint(changes: Value) -> String {
    let mut claims = json!({
        "iss": ISSUER, "sub": SUBJECT, "aud": RESOURCE, "client_id": "claude", "exp": now() + 600,
        "iat": now(), "jti": "j1", "scope": "courrier.read",
    });
    merge(&mut claims, changes);
    sign(&claims)
}

pub fn known() -> Arc<Identities> {
    Arc::new(Identities::with(ISSUER, SUBJECT, 42))
}

pub fn config(identities: Arc<dyn IdentityStore>) -> Config {
    Config {
        issuer: ISSUER.into(),
        resource: RESOURCE.into(),
        scope_prefix: "courrier".into(),
        audience: APP_AUDIENCE.into(),
        identities,
        provision: false,
        accounts: None,
        http: fixture_client(),
    }
}

pub async fn verifier(identities: Arc<dyn IdentityStore>) -> Verifier {
    Verifier::new(config(identities)).await.unwrap()
}

pub struct Broken;

#[async_trait::async_trait]
impl IdentityStore for Broken {
    async fn find(&self, _: &str, _: &str) -> Result<StoredIdentity, StoreError> {
        Err(StoreError::other("the database is down"))
    }

    async fn save(&self, _: &StoredIdentity) -> Result<(), StoreError> {
        Err(StoreError::other("the database is down"))
    }

    async fn mark_roles_synced(&self, _: &str, _: &str, _: OffsetDateTime) -> Result<(), StoreError> {
        Err(StoreError::other("the database is down"))
    }

    async fn list_by_user(&self, _: i64) -> Result<Vec<StoredIdentity>, StoreError> {
        Err(StoreError::other("the database is down"))
    }
}
