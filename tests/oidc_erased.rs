#![cfg(feature = "oidc")]

mod common;

use axum::body::Body;
use common::flow::Browser;
use common::ledger::{guarded, token, upserts};
use common::provider::ISSUER;
use http::Request;
use porte::oidc::ProvisionError;
use porte::{IdentityStore, SubjectErased};

#[tokio::test]
async fn the_callback_refuses_an_erased_subject() {
    let (flow, ledger) = guarded().await;
    ledger.erase("subject-1");
    let callback = flow.login(&mut Browser::default(), "").await;
    assert_eq!(
        (callback.status, callback.header("location").as_deref()),
        (302, Some("https://app.test/login?error=this+account+was+deleted"))
    );
    assert_eq!(upserts(&flow), 0, "an erased subject reached the user write");
    assert!(flow.identities.find(ISSUER, "subject-1").await.is_err());
}

#[tokio::test]
async fn provisioning_refuses_an_erased_subject() {
    let (flow, ledger) = guarded().await;
    ledger.erase("subject-1");
    assert!(matches!(flow.kit.provision_bearer(&token("subject-1")).await, Err(ProvisionError::Erased)));
    assert_eq!(upserts(&flow), 0, "an erased subject reached the user write");
}

#[tokio::test]
async fn an_unreadable_ledger_fails_closed_without_a_refusal() {
    let (flow, ledger) = guarded().await;
    *ledger.fail.lock().unwrap() = true;
    assert!(matches!(flow.kit.provision_bearer(&token("subject-1")).await, Err(ProvisionError::Store(_))));
    let callback = flow.login(&mut Browser::default(), "").await;
    assert_eq!(callback.header("location").as_deref(), Some("https://app.test/login?error=could+not+sign+you+in"));
    assert_eq!(upserts(&flow), 0, "an account was created while the ledger was unreadable");
}

#[tokio::test]
async fn other_subjects_sign_in_beside_an_erased_one() {
    let (flow, ledger) = guarded().await;
    ledger.erase("someone-erased");
    assert!(flow.kit.provision_bearer(&token("subject-2")).await.is_ok());
    let callback = flow.login(&mut Browser::default(), "").await;
    assert_eq!((callback.status, callback.header("location").as_deref()), (302, Some("https://app.test/")));
}

#[tokio::test]
async fn the_profile_sync_refuses_a_subject_erased_after_sign_in() {
    let (flow, ledger) = guarded().await;
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    ledger.erase("subject-1");
    let mut row = flow.identities.find(ISSUER, "subject-1").await.unwrap();
    row.synced_at = Some(time::OffsetDateTime::now_utc() - std::time::Duration::from_secs(600));
    flow.identities.save(&row).await.unwrap();
    let request = Request::post("/auth/sync-profile").header(porte::CSRF_HEADER_NAME, "1").body(Body::empty());
    let answer = browser.send(&flow, request.unwrap()).await;
    assert_eq!(answer.status, 403, "{}", answer.body);
    assert!(answer.body.contains("permission_denied"), "{}", answer.body);
    assert_eq!(upserts(&flow), 1, "the sync wrote the erased profile");
}

#[test]
fn the_refusal_names_its_cause() {
    let mut refused = tronc::Error::forbidden("this account was deleted");
    assert!(!SubjectErased::caused(&refused));
    refused.cause = Some(Box::new(SubjectErased));
    assert!(SubjectErased::caused(&refused));
}
