#![cfg(feature = "mcp")]

mod common;

use std::sync::Arc;

use common::idp::fixture_client;
use common::mcp::{config, mint};
use common::memory::Sessions;
use common::stores::{Codes, Identities, Users};
use porte::mcpauth::{Verifier, VerifyError};
use porte::oidc::{Deps, Kit};
use porte::session::{self, Manager};
use serde_json::json;

async fn kit(identities: Arc<Identities>, users: Arc<Users>) -> Kit {
    let cfg = common::kit::config_from(&common::kit::oidc_env(&[]));
    let manager = Manager::new(&cfg, session::Deps { sessions: Arc::new(Sessions::default()), now: None });
    let deps = Deps {
        users,
        identities,
        codes: Arc::new(Codes::default()),
        sessions: manager,
        config_extra: None,
        http: Some(fixture_client()),
        now: None,
    };
    Kit::new(&cfg, deps).await.unwrap()
}

async fn provisioning() -> (Verifier, Arc<Users>) {
    let (identities, users) = (Arc::new(Identities::default()), Arc::new(Users::default()));
    let accounts = kit(identities.clone(), users.clone()).await;
    let cfg = porte::mcpauth::Config { provision: true, accounts: Some(accounts), ..config(identities) };
    (Verifier::new(cfg).await.unwrap(), users)
}

#[tokio::test]
async fn a_first_mcp_call_provisions_the_account() {
    let (verifier, users) = provisioning().await;
    let token = mint(json!({ "email": "Ann@Example.test", "email_verified": true }));
    assert_eq!(verifier.verify(&token).await.unwrap().user_id, "7");
    verifier.verify(&token).await.unwrap();
    assert_eq!(users.claims.lock().unwrap().len(), 1, "an existing account was provisioned again");
}

#[tokio::test]
async fn a_refused_provisioning_is_an_invalid_token() {
    let (verifier, users) = provisioning().await;
    let unverified = mint(json!({ "email": "ann@example.test", "email_verified": false }));
    assert_eq!(verifier.verify(&unverified).await, Err(VerifyError::InvalidToken));
    assert!(users.claims.lock().unwrap().is_empty());
}

#[tokio::test]
async fn without_provision_a_newcomer_is_refused() {
    let verifier = Verifier::new(config(Arc::new(Identities::default()))).await.unwrap();
    let token = mint(json!({ "email": "ann@example.test", "email_verified": true }));
    assert_eq!(verifier.verify(&token).await, Err(VerifyError::InvalidToken));
}

#[tokio::test]
async fn accounts_under_another_issuer_are_refused() {
    let identities = Arc::new(Identities::default());
    let accounts = kit(identities.clone(), Arc::new(Users::default())).await;
    let cfg = porte::mcpauth::Config {
        provision: true,
        accounts: Some(accounts),
        issuer: "https://other.test".into(),
        ..config(identities)
    };
    assert!(Verifier::new(cfg).await.is_err());
}
