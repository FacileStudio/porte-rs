#![cfg(feature = "oidc")]

mod common;

use std::time::Duration;

use axum::body::Body;
use common::flow::{Browser, harness};
use common::provider::ISSUER;
use http::Request;
use porte::IdentityStore;

#[tokio::test]
async fn the_roles_claim_rides_the_flow_when_configured() {
    let flow = harness(|cfg, idp| {
        cfg.claims_scope = "facile".into();
        idp.state.lock().unwrap().roles = Some(vec!["admin".into()]);
    })
    .await
    .unwrap();
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    let me = browser.send(&flow, Request::get("/whoami").body(Body::empty()).unwrap()).await;
    assert_eq!(me.body, "7 admin");
}

#[tokio::test]
async fn the_callback_fails_loudly_when_the_roles_claim_never_arrives() {
    let flow = harness(|cfg, _| cfg.claims_scope = "facile".into()).await.unwrap();
    let callback = flow.login(&mut Browser::default(), "").await;
    assert_eq!(callback.header("location").unwrap(), "https://app.test/login?error=could+not+sign+you+in");
    assert_eq!(flow.sessions.count(7), 0);
}

#[tokio::test]
async fn the_kit_refuses_a_roles_scope_the_provider_does_not_offer() {
    let refused = harness(|cfg, idp| {
        cfg.claims_scope = "facile".into();
        idp.state.lock().unwrap().scopes_supported = vec!["openid".into(), "email".into()];
    })
    .await
    .err()
    .expect("a missing roles scope booted");
    assert!(refused.0.contains("is not offered by"), "{refused}");
}

#[tokio::test]
async fn stale_roles_are_refreshed_once_the_access_token_expired() {
    let flow = harness(|cfg, idp| {
        cfg.claims_scope = "facile".into();
        cfg.claims_ttl = Duration::from_secs(1);
        idp.state.lock().unwrap().roles = Some(vec!["admin".into()]);
    })
    .await
    .unwrap();
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    let mut row = flow.identities.find(ISSUER, "subject-1").await.unwrap();
    row.roles_synced_at = Some(time::OffsetDateTime::now_utc() - Duration::from_secs(60));
    row.tokens.expiry = Some(time::OffsetDateTime::now_utc() - Duration::from_secs(60));
    flow.identities.save(&row).await.unwrap();
    flow.provider.state.lock().unwrap().roles = Some(vec!["staff".into()]);
    let me = browser.send(&flow, Request::get("/whoami").body(Body::empty()).unwrap()).await;
    assert_eq!(me.body, "7 staff");
    let refreshed = flow.identities.find(ISSUER, "subject-1").await.unwrap();
    assert!(refreshed.tokens.expiry.unwrap() > time::OffsetDateTime::now_utc());
}

#[tokio::test]
async fn a_failed_refresh_keeps_the_cached_roles_and_records_the_attempt() {
    let flow = harness(|cfg, idp| {
        cfg.claims_scope = "facile".into();
        idp.state.lock().unwrap().roles = Some(vec!["admin".into()]);
    })
    .await
    .unwrap();
    let mut browser = Browser::default();
    flow.login(&mut browser, "").await;
    let mut row = flow.identities.find(ISSUER, "subject-1").await.unwrap();
    let stale = time::OffsetDateTime::now_utc() - Duration::from_secs(3600);
    (row.roles_synced_at, row.tokens.refresh_token) = (Some(stale), "dead".into());
    row.tokens.expiry = Some(stale);
    flow.identities.save(&row).await.unwrap();
    let me = browser.send(&flow, Request::get("/whoami").body(Body::empty()).unwrap()).await;
    assert_eq!(me.body, "7 admin");
    assert!(flow.identities.find(ISSUER, "subject-1").await.unwrap().roles_synced_at.unwrap() > stale);
}
