#![cfg(feature = "oidc")]

mod common;

use common::flow::harness;
use common::provider::ISSUER;
use porte::IdentityStore;
use porte::jwt::{Claims, Profile};
use porte::oidc::ProvisionError;

fn token(verified: Option<bool>) -> Claims {
    Claims {
        subject: "subject-1".into(),
        email: "User@Example.test".into(),
        name: "Test User".into(),
        roles: None,
        scopes: vec!["app.read".into()],
        actor: String::new(),
        audience: vec!["app-client".into()],
        client_id: "claude".into(),
        id: String::new(),
        expires_at: time::OffsetDateTime::now_utc(),
        profile: Profile { email_verified: verified, ..Profile::default() },
    }
}

#[tokio::test]
async fn a_first_bearer_call_creates_the_account_the_login_would() {
    let flow = harness(|_, _| {}).await.unwrap();
    let identity = flow.kit.provision_bearer(&token(Some(true))).await.unwrap();
    assert_eq!((identity.user_id, identity.subject.as_str()), (7, "subject-1"));
    assert_eq!(flow.users.claims.lock().unwrap()[0].email, "user@example.test");
    assert!(flow.identities.find(ISSUER, "subject-1").await.is_ok());
    flow.kit.provision_bearer(&token(Some(true))).await.unwrap();
    assert_eq!(flow.users.claims.lock().unwrap().len(), 1, "an existing account was provisioned again");
}

#[tokio::test]
async fn provisioning_refuses_an_email_nobody_vouched_for() {
    let flow = harness(|_, _| {}).await.unwrap();
    for verified in [None, Some(false)] {
        let refused = flow.kit.provision_bearer(&token(verified)).await;
        assert!(matches!(refused, Err(ProvisionError::Refused(_))), "{verified:?} provisioned");
    }
    let mut anonymous = token(Some(true));
    anonymous.email.clear();
    assert!(matches!(flow.kit.provision_bearer(&anonymous).await, Err(ProvisionError::Refused(_))));
    assert!(flow.users.claims.lock().unwrap().is_empty());
}

#[tokio::test]
async fn provisioning_needs_roles_when_the_login_does() {
    let flow = harness(|cfg, _| cfg.claims_scope = "facile".into()).await.unwrap();
    assert!(matches!(flow.kit.provision_bearer(&token(Some(true))).await, Err(ProvisionError::Refused(_))));
    let mut with_roles = token(Some(true));
    with_roles.roles = Some(vec!["admin".into()]);
    assert!(flow.kit.provision_bearer(&with_roles).await.is_ok());
}

#[tokio::test]
async fn concurrent_first_calls_create_one_account() {
    let flow = harness(|_, _| {}).await.unwrap();
    let calls = (0..8).map(|_| {
        let kit = flow.kit.clone();
        tokio::spawn(async move { kit.provision_bearer(&token(Some(true))).await.unwrap().user_id })
    });
    for call in calls.collect::<Vec<_>>() {
        assert_eq!(call.await.unwrap(), 7);
    }
    assert_eq!(flow.users.claims.lock().unwrap().len(), 1);
}
